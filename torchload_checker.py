#!/usr/bin/env python3
"""
torchload-checker — Scan Python repos for unsafe torch.load() and pickle usage.

Detects CWE-502 (Deserialization of Untrusted Data) patterns in ML/AI codebases.
Based on EPNA's vulnerability research that found 20+ real CVEs.

Usage:
    python3 torchload_checker.py /path/to/repo
    python3 torchload_checker.py /path/to/repo --json
    python3 torchload_checker.py /path/to/repo --severity high
"""

__version__ = "0.11.0"

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional

@dataclass
class Finding:
    file: str
    line: int
    pattern: str
    code: str
    severity: str
    cwe: str
    description: str

PATTERNS = [
    {
        "name": "torch.load(weights_only=False)",
        "regex": r"torch\.load\s*\([^)]*weights_only\s*=\s*False",
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "desc": "Explicit weights_only=False enables arbitrary code execution via pickle deserialization"
    },
    {
        "name": "torch.load(no weights_only)",
        "regex": r"torch\.load\s*\((?!.*weights_only)[^)]*\)",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "torch.load without weights_only parameter — defaults to unsafe in PyTorch <2.6"
    },
    {
        "name": "pickle.load/loads",
        "regex": r"(?<!\w)pickle\.(load|loads)\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "Direct pickle deserialization allows arbitrary code execution"
    },
    {
        "name": "pickle.Unpickler",
        "regex": r"(?<!\w)pickle\.Unpickler\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "Pickle Unpickler can execute arbitrary code during deserialization"
    },
    {
        "name": "cloudpickle.load/loads",
        "regex": r"(?<!\w)cloudpickle\.(load|loads)\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "cloudpickle deserialization allows arbitrary code execution"
    },
    {
        "name": "dill.load/loads",
        "regex": r"(?<!\w)dill\.(load|loads)\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "dill deserialization allows arbitrary code execution"
    },
    {
        "name": "joblib.load",
        "regex": r"joblib\.load\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "joblib.load uses pickle internally — unsafe with untrusted data"
    },
    {
        "name": "yaml.load (unsafe)",
        "regex": r"yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.(?:Safe|CSafe)Loader)[^)]*\)",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "yaml.load without SafeLoader allows arbitrary code execution"
    },
    {
        "name": "shelve.open",
        "regex": r"shelve\.open\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "shelve uses pickle internally — unsafe with untrusted data"
    },
    {
        "name": "numpy.load(allow_pickle=True)",
        "regex": r"(?:np|numpy)\.load\s*\([^)]*allow_pickle\s*=\s*True",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "numpy.load with allow_pickle=True enables arbitrary code execution via pickle"
    },
    {
        "name": "pandas.read_pickle",
        "regex": r"(?:pd|pandas)\.read_pickle\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "pandas.read_pickle uses pickle internally — unsafe with untrusted data"
    },
    {
        "name": "marshal.loads",
        "regex": r"marshal\.loads?\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "marshal.loads can execute arbitrary code via crafted bytecode objects"
    },
    {
        "name": "_pickle.loads",
        "regex": r"(?<!\w)_pickle\.(loads?|Unpickler)\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "C-accelerated pickle module — same deserialization risks as pickle"
    },
    {
        "name": "torch.save(user data)",
        "regex": r"torch\.save\s*\([^)]*request\.|torch\.save\s*\([^)]*user_|torch\.save\s*\([^)]*upload",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "torch.save with potentially user-controlled data — review data source"
    },
    {
        "name": "tf.keras.models.load_model (unsafe)",
        "regex": r"(?:tf\.keras|keras)\.models\.load_model\s*\([^)]*(?:compile\s*=\s*True|custom_objects)",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "Keras load_model with compile=True or custom_objects can execute arbitrary code via Lambda layers"
    },
    {
        "name": "onnx.load (external data)",
        "regex": r"onnx\.load\s*\([^)]*load_external_data\s*=\s*True",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "ONNX load with external data may load from untrusted file paths"
    },
    {
        "name": "__reduce__ deserialization hook",
        "regex": r"def\s+__reduce(?:_ex)?__\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "Custom __reduce__ method — used by pickle for deserialization, potential RCE vector"
    },
    {
        "name": "exec/eval in model loading",
        "regex": r"(?:exec|eval)\s*\([^)]*(?:model|weight|checkpoint|ckpt|state_dict)",
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "desc": "exec/eval with model-related data — direct code execution vulnerability"
    },
    {
        "name": "scipy.io.loadmat",
        "regex": r"scipy\.io\.loadmat\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "scipy.io.loadmat can deserialize pickle objects embedded in .mat files"
    },
    {
        "name": "torch.package import",
        "regex": r"torch\.package\.PackageImporter\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "torch.package imports can execute arbitrary Python code from untrusted .pt archives"
    },
    {
        "name": "transformers pipeline (trust_remote_code)",
        "regex": r"(?:pipeline|from_pretrained)\s*\([^)]*trust_remote_code\s*=\s*True",
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "desc": "trust_remote_code=True allows execution of arbitrary code from HuggingFace Hub models"
    },
    {
        "name": "jsonpickle.decode",
        "regex": r"jsonpickle\.decode\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "jsonpickle.decode can instantiate arbitrary objects — equivalent to pickle.loads for JSON"
    },
    {
        "name": "catboost.CatBoost.load_model",
        "regex": r"(?:catboost|CatBoost|CatBoostClassifier|CatBoostRegressor)\.load_model\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "CatBoost model loading may deserialize untrusted model files"
    },
    {
        "name": "zipfile extract (model files)",
        "regex": r"(?:ZipFile|zipfile)\s*\([^)]*\)\.(?:extract|extractall)\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-22",
        "desc": "Zip extraction without path validation — potential path traversal in model archives (Zip Slip)"
    },
    {
        "name": "torch.jit.load",
        "regex": r"torch\.jit\.load\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "TorchScript loading can execute arbitrary code via custom operators and __reduce__-based payloads"
    },
    {
        "name": "tf.saved_model.load",
        "regex": r"tf\.saved_model\.load\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "TensorFlow SavedModel can contain arbitrary ops — verify model source is trusted"
    },
    {
        "name": "sklearn model via pickle",
        "regex": r"(?:sklearn|joblib)\..*(?:load|dump)\s*\(.*\.pkl",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "scikit-learn models serialized via pickle/joblib — unsafe with untrusted .pkl files"
    },
    {
        "name": "onnxruntime InferenceSession",
        "regex": r"onnxruntime\.InferenceSession\s*\([^)]*(?:custom_op|register)",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "ONNX Runtime with custom operators can load and execute arbitrary shared libraries"
    },
    {
        "name": "safetensors disabled/bypassed",
        "regex": r"use_safetensors\s*=\s*False",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "Explicitly disabling safetensors forces fallback to unsafe pickle-based loading"
    },
    {
        "name": "torch.hub.load (untrusted repo)",
        "regex": r"torch\.hub\.load\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "torch.hub.load downloads and executes code from GitHub repos — verify repo is trusted"
    },
    {
        "name": "lightning load_from_checkpoint",
        "regex": r"\.load_from_checkpoint\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "PyTorch Lightning load_from_checkpoint uses pickle internally — unsafe with untrusted checkpoints"
    },
    {
        "name": "xgboost pickle model load",
        "regex": r"(?:xgb|xgboost)\.Booster\s*\([^)]*model_file|pickle\.load.*\.(?:xgb|bst)",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "XGBoost model loading may use pickle format — verify model source is trusted"
    },
    {
        "name": "accelerate load_checkpoint",
        "regex": r"load_checkpoint_and_dispatch\s*\(|load_checkpoint_in_model\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "HuggingFace Accelerate checkpoint loading can deserialize pickle-based model files"
    },
    {
        "name": "cPickle.load/loads",
        "regex": r"cPickle\.(load|loads)\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "cPickle (Python 2 C-accelerated pickle) allows arbitrary code execution via deserialization"
    },
    {
        "name": "torch.utils.model_zoo.load_url",
        "regex": r"torch\.utils\.model_zoo\.load_url\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "model_zoo.load_url downloads and deserializes models from URLs via pickle"
    },
    {
        "name": "mmcv/mmengine.load (pickle)",
        "regex": r"(?:mmcv|mmengine)\.(?:load|FileClient)\s*\([^)]*\.(?:pkl|pickle|pth)",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "OpenMMLab mmcv/mmengine.load uses pickle for .pkl/.pth files — unsafe with untrusted data"
    },
    {
        "name": "paddle.load",
        "regex": r"paddle\.load\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "PaddlePaddle paddle.load uses pickle by default — unsafe with untrusted model files"
    },
    {
        "name": "mlflow model load",
        "regex": r"mlflow\.(?:pytorch|sklearn|pyfunc|tensorflow|keras)\.load_model\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "MLflow model loading may deserialize pickle-based artifacts from untrusted sources"
    },
    {
        "name": "bentoml model load",
        "regex": r"bentoml\.(?:pytorch|sklearn|picklable_model)\.(?:load_model|load_runner)\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "BentoML model loading may use pickle internally for model deserialization"
    },
    {
        "name": "ray checkpoint load",
        "regex": r"(?:Checkpoint\.from_directory|load_checkpoint)\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "Ray/Tune checkpoint loading may deserialize pickle-based model state"
    },
    {
        "name": "torch.load map_location with URL",
        "regex": r"torch\.load\s*\([^)]*(?:http://|https://|ftp://)",
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "desc": "torch.load from URL — loading untrusted remote model enables arbitrary code execution"
    },
    {
        "name": "hickle.load",
        "regex": r"hickle\.load\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "hickle.load uses pickle internally for non-native types — unsafe with untrusted HDF5 files"
    },
    {
        "name": "torch.load(pickle_module)",
        "regex": r"torch\.load\s*\([^)]*pickle_module\s*=",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "torch.load with custom pickle_module — may bypass safety checks or introduce custom deserialization"
    },
    {
        "name": "keras.models.load_model (generic)",
        "regex": r"(?:tf\.keras|keras)\.models\.load_model\s*\([^)]*(?:\.h5|\.keras|\.hdf5)",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "Keras load_model from file — models with Lambda layers can execute arbitrary code"
    },
    {
        "name": "skops.io.load (no trusted)",
        "regex": r"skops\.io\.load\s*\((?!.*trusted)[^)]*\)",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "skops.io.load without trusted types list — allows deserialization of arbitrary sklearn objects"
    },
    {
        "name": "wandb artifact download + pickle",
        "regex": r"wandb\.(?:Api\(\)|init).*\.download|wandb\.restore\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "WandB artifact download — models may be pickle-serialized from untrusted sources"
    },
    {
        "name": "torch.distributed.checkpoint.load",
        "regex": r"torch\.distributed\.checkpoint\.load\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "Distributed checkpoint loading may deserialize pickle-based model shards"
    },
    {
        "name": "keras Lambda layer in model",
        "regex": r"keras\.layers\.Lambda\s*\(|Lambda\s*\(\s*lambda",
        "severity": "MEDIUM",
        "cwe": "CWE-94",
        "desc": "Keras Lambda layers execute arbitrary code — models with Lambda layers are unsafe to load from untrusted sources"
    },
    {
        "name": "huggingface auto_model (trust_remote_code)",
        "regex": r"Auto(?:Model|Tokenizer|Config|Feature)(?:ForCausalLM|ForSequenceClassification|ForTokenClassification)?\.from_pretrained\s*\([^)]*trust_remote_code\s*=\s*True",
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "desc": "HuggingFace Auto class with trust_remote_code=True executes arbitrary code from model repos"
    },
    {
        "name": "gradio.load (remote)",
        "regex": r"gr(?:adio)?\.load\s*\([^)]*(?:http|huggingface|spaces/)",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "Gradio.load from remote space/URL may execute untrusted code from remote model endpoints"
    },
    {
        "name": "transformers.utils.hub.cached_file (legacy)",
        "regex": r"cached_file\s*\([^)]*\.bin",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "Loading .bin model files via cached_file uses pickle — prefer .safetensors format"
    },
    {
        "name": "vllm model load (trust_remote_code)",
        "regex": r"(?:LLM|AsyncLLMEngine|EngineArgs)\s*\([^)]*trust_remote_code\s*=\s*True",
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "desc": "vLLM with trust_remote_code=True executes arbitrary code from HuggingFace model repos"
    },
    {
        "name": "diffusers from_pretrained (trust_remote_code)",
        "regex": r"\.from_pretrained\s*\([^)]*trust_remote_code\s*=\s*True",
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "desc": "Diffusers/model loading with trust_remote_code=True allows arbitrary code execution"
    },
    {
        "name": "flax.serialization.from_bytes",
        "regex": r"flax\.serialization\.from_bytes\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "Flax from_bytes uses msgpack — may deserialize untrusted model state"
    },
    {
        "name": "jax numpy load (allow_pickle)",
        "regex": r"(?:jax\.numpy|jnp)\.load\s*\([^)]*allow_pickle\s*=\s*True",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "JAX numpy.load with allow_pickle=True enables arbitrary code execution"
    },
    {
        "name": "tensorrt deserialize_cuda_engine",
        "regex": r"(?:trt|tensorrt)\.Runtime\s*\([^)]*\)\.deserialize_cuda_engine\s*\(|deserialize_cuda_engine\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "TensorRT engine deserialization can execute arbitrary CUDA kernels from untrusted .engine/.trt files"
    },
    {
        "name": "mxnet model load",
        "regex": r"(?:mx|mxnet)\.(?:nd\.load|model\.load_checkpoint|gluon\.nn\.SymbolBlock\.imports)\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "MXNet model loading may deserialize untrusted model parameters"
    },
    {
        "name": "orbax checkpoint restore",
        "regex": r"(?:orbax|CheckpointManager)\.(?:restore|load)\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "Orbax checkpoint restore may load untrusted serialized model state"
    },
    {
        "name": "ultralytics YOLO load",
        "regex": r"YOLO\s*\([^)]*(?:http|ftp|\.pt|\.engine)",
        "severity": "MEDIUM",
        "cwe": "CWE-502",
        "desc": "Ultralytics YOLO model loading from untrusted .pt files uses pickle internally"
    },
]

MITIGATIONS = {
    "safetensors": r"(?:from\s+safetensors|import\s+safetensors|\.safetensors)",
    "weights_only_true": r"weights_only\s*=\s*True",
    "safe_loader": r"yaml\.SafeLoader|yaml\.safe_load",
}

SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.tox', '.eggs', 'venv', '.venv', 'env'}
TEST_DIRS = {'test', 'tests', 'testing', 'test_', 'doc', 'docs', 'examples', 'example', 'demo', 'demos', 'benchmark', 'benchmarks'}

SUPPRESS_MARKERS = {'# nosec', '# noqa: CWE-502', '# torchload-ignore'}

def _is_suppressed(line: str) -> bool:
    """Check if a line has an inline suppression comment."""
    return any(marker in line for marker in SUPPRESS_MARKERS)

def _is_skip_line(stripped: str) -> bool:
    """Check if a line should be skipped (comment, string def, logging, etc.)."""
    if stripped.startswith('#'):
        return True
    if re.match(r'^["\'].*["\'],?\s*$', stripped):
        return True
    if re.match(r'^\s*"(name|regex|desc|description|pattern)":', stripped):
        return True
    # Skip logging/print statements that merely mention patterns
    if re.match(r'^\s*(?:logger|logging)\.\w+\s*\(', stripped):
        return True
    # Skip raise/assert statements referencing patterns in error messages
    if re.match(r'^\s*raise\s+\w+Error\s*\(["\']', stripped):
        return True
    # Skip import statements (importing pickle isn't calling it)
    if re.match(r'^\s*(?:from\s+\S+\s+)?import\s+', stripped):
        return True
    # Skip print statements that merely reference patterns
    if re.match(r'^\s*print\s*\(', stripped):
        return True
    # Skip assert statements in test code
    if re.match(r'^\s*assert\s+', stripped):
        return True
    # Skip decorator lines
    if stripped.startswith('@'):
        return True
    # Skip type annotations and docstring-like variables
    if re.match(r'^\s*\w+\s*:\s*str\s*=\s*["\']', stripped):
        return True
    # Skip f-string/format references in error messages
    if re.match(r'^\s*(?:msg|message|err|error|warning)\s*=\s*[f"\']', stripped):
        return True
    return False

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB — skip huge generated files

def scan_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        size = os.path.getsize(filepath)
        if size > MAX_FILE_SIZE:
            return findings
        with open(filepath, 'r', errors='ignore') as f:
            lines = f.readlines()
    except (PermissionError, IsADirectoryError, OSError):
        return findings

    in_multiline_string = False
    matched_lines = set()

    # Pass 1: single-line pattern matching
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('"""') or stripped.startswith("'''"):
            delimiter = stripped[:3]
            if stripped.count(delimiter) == 1:
                in_multiline_string = not in_multiline_string
            continue
        if in_multiline_string:
            continue
        if _is_skip_line(stripped):
            continue
        if _is_suppressed(line):
            continue
        for pat in PATTERNS:
            if re.search(pat["regex"], line):
                matched_lines.add(i)
                findings.append(Finding(
                    file=filepath,
                    line=i,
                    pattern=pat["name"],
                    code=stripped[:120],
                    severity=pat["severity"],
                    cwe=pat["cwe"],
                    description=pat["desc"]
                ))

    # Pass 2: multi-line call detection (join lines with unclosed parens)
    in_multiline_string = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        lineno = i + 1

        if stripped.startswith('"""') or stripped.startswith("'''"):
            delimiter = stripped[:3]
            if stripped.count(delimiter) == 1:
                in_multiline_string = not in_multiline_string
            i += 1
            continue
        if in_multiline_string or _is_skip_line(stripped) or _is_suppressed(line):
            i += 1
            continue

        # Check if line has an opening paren without a closing one (multi-line call)
        open_count = line.count('(') - line.count(')')
        if open_count > 0 and lineno not in matched_lines:
            joined = line.rstrip('\n')
            start_line = lineno
            j = i + 1
            while j < len(lines) and open_count > 0 and (j - i) < 10:
                next_line = lines[j].strip()
                if next_line.startswith('#'):
                    j += 1
                    continue
                joined += ' ' + next_line
                open_count += lines[j].count('(') - lines[j].count(')')
                j += 1

            for pat in PATTERNS:
                if re.search(pat["regex"], joined):
                    if start_line not in matched_lines:
                        matched_lines.add(start_line)
                        findings.append(Finding(
                            file=filepath,
                            line=start_line,
                            pattern=pat["name"],
                            code=stripped[:120],
                            severity=pat["severity"],
                            cwe=pat["cwe"],
                            description=pat["desc"]
                        ))
        i += 1

    return findings

def scan_repo(repo_path: str, min_severity: str = "LOW", exclude_tests: bool = False) -> List[Finding]:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_sev_val = sev_order.get(min_severity.upper(), 3)

    all_findings = []
    repo = Path(repo_path)

    for py_file in repo.rglob("*.py"):
        if any(skip in py_file.parts for skip in SKIP_DIRS):
            continue
        if exclude_tests and any(t in py_file.parts for t in TEST_DIRS):
            continue
        if exclude_tests and (py_file.name.startswith("test_") or py_file.name.endswith("_test.py")):
            continue
        findings = scan_file(str(py_file))
        all_findings.extend(f for f in findings if sev_order.get(f.severity, 3) <= min_sev_val)

    all_findings.sort(key=lambda f: sev_order.get(f.severity, 3))
    return all_findings

def check_mitigations(repo_path: str) -> dict:
    results = {}
    repo = Path(repo_path)
    for name, regex in MITIGATIONS.items():
        found = False
        for py_file in repo.rglob("*.py"):
            if any(skip in py_file.parts for skip in SKIP_DIRS):
                continue
            try:
                content = py_file.read_text(errors='ignore')
                if re.search(regex, content):
                    found = True
                    break
            except (PermissionError, IsADirectoryError):
                continue
        results[name] = found
    return results

def findings_to_sarif(findings: List[Finding], repo_path: str) -> dict:
    """Convert findings to SARIF format for GitHub Code Scanning."""
    sev_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    rules = {}
    results = []

    for f in findings:
        rule_id = f.pattern.replace(" ", "-").replace("(", "").replace(")", "").lower()
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.pattern,
                "shortDescription": {"text": f.pattern},
                "fullDescription": {"text": f.description},
                "helpUri": "https://cwe.mitre.org/data/definitions/502.html",
                "properties": {"tags": ["security", "CWE-502", "deserialization"]}
            }

        rel_path = os.path.relpath(f.file, repo_path)
        results.append({
            "ruleId": rule_id,
            "level": sev_map.get(f.severity, "warning"),
            "message": {"text": f"{f.description}\n\nCode: `{f.code}`"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel_path},
                    "region": {"startLine": f.line}
                }
            }]
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "torchload-checker",
                    "version": __version__,
                    "informationUri": "https://github.com/jeremysommerfeld8910-cpu/torchload-checker",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }]
    }

def get_git_changed_files(repo_path: str, diff_ref: str = "HEAD") -> List[str]:
    """Get list of .py files changed relative to a git ref (branch, commit, tag)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", diff_ref, "--", "*.py"],
            capture_output=True, text=True, cwd=repo_path
        )
        if result.returncode != 0:
            # Try as branch comparison (e.g., "main")
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACMR", diff_ref + "...HEAD", "--", "*.py"],
                capture_output=True, text=True, cwd=repo_path
            )
        files = [os.path.join(repo_path, f.strip()) for f in result.stdout.strip().split('\n') if f.strip()]
        # Also include unstaged/untracked .py files
        result2 = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", "--", "*.py"],
            capture_output=True, text=True, cwd=repo_path
        )
        unstaged = [os.path.join(repo_path, f.strip()) for f in result2.stdout.strip().split('\n') if f.strip()]
        return list(set(files + unstaged))
    except (FileNotFoundError, subprocess.SubprocessError):
        return []


def scan_files(file_list: List[str], min_severity: str = "LOW") -> List[Finding]:
    """Scan a specific list of files."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_sev_val = sev_order.get(min_severity.upper(), 3)
    all_findings = []
    for filepath in file_list:
        if os.path.isfile(filepath) and filepath.endswith('.py'):
            findings = scan_file(filepath)
            all_findings.extend(f for f in findings if sev_order.get(f.severity, 3) <= min_sev_val)
    all_findings.sort(key=lambda f: sev_order.get(f.severity, 3))
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Scan repos for unsafe deserialization (CWE-502)")
    parser.add_argument("path", help="Path to repository to scan")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--sarif", action="store_true", help="Output as SARIF for GitHub Code Scanning")
    parser.add_argument("--severity", default="LOW", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity to report (default: LOW)")
    parser.add_argument("--exclude-tests", action="store_true",
                        help="Exclude test/, doc/, example/ directories and test_*.py files")
    parser.add_argument("--summary", action="store_true",
                        help="Show only summary counts by severity")
    parser.add_argument("--baseline", metavar="FILE",
                        help="Baseline JSON file — only report new findings not in baseline")
    parser.add_argument("--save-baseline", metavar="FILE",
                        help="Save current findings as baseline JSON file")
    parser.add_argument("--fail-on", default=None,
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Only exit non-zero if findings at this severity or above exist")
    parser.add_argument("--diff", metavar="REF", nargs="?", const="HEAD",
                        help="Only scan .py files changed relative to a git ref (default: HEAD). "
                             "Example: --diff main, --diff HEAD~3")
    parser.add_argument("--version", action="version", version=f"torchload-checker {__version__}")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a directory", file=sys.stderr)
        sys.exit(1)

    if args.diff is not None:
        changed = get_git_changed_files(args.path, args.diff)
        if not changed:
            print(f"No changed .py files found relative to {args.diff}")
            sys.exit(0)
        findings = scan_files(changed, args.severity)
    else:
        exclude = getattr(args, 'exclude_tests', False)
        findings = scan_repo(args.path, args.severity, exclude_tests=exclude)
    mitigations = check_mitigations(args.path)

    # Save baseline if requested
    if args.save_baseline:
        baseline_data = [{"file": os.path.relpath(f.file, args.path), "line": f.line,
                          "pattern": f.pattern} for f in findings]
        with open(args.save_baseline, 'w') as bf:
            json.dump(baseline_data, bf, indent=2)
        print(f"Saved baseline with {len(baseline_data)} findings to {args.save_baseline}")
        sys.exit(0)

    # Filter against baseline if provided
    if args.baseline:
        try:
            with open(args.baseline) as bf:
                baseline = json.load(bf)
            baseline_keys = {(b["file"], b["pattern"]) for b in baseline}
            findings = [f for f in findings
                        if (os.path.relpath(f.file, args.path), f.pattern) not in baseline_keys]
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            print(f"Warning: Could not load baseline {args.baseline}: {e}", file=sys.stderr)

    if args.sarif:
        sarif = findings_to_sarif(findings, args.path)
        print(json.dumps(sarif, indent=2))
    elif args.json:
        output = {
            "repo": args.path,
            "total_findings": len(findings),
            "findings": [asdict(f) for f in findings],
            "mitigations": mitigations
        }
        print(json.dumps(output, indent=2))
    elif args.summary:
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        print(f"torchload-checker: {args.path}")
        print(f"  Total: {len(findings)} findings")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in sev_counts:
                print(f"  {sev}: {sev_counts[sev]}")
        for name, found in mitigations.items():
            print(f"  {name}: {'YES' if found else 'NO'}")
    else:
        print(f"\n{'='*60}")
        print(f"  torchload-checker — CWE-502 Scanner")
        print(f"  Repo: {args.path}")
        print(f"{'='*60}\n")

        if not findings:
            print("  No unsafe deserialization patterns found.")
        else:
            print(f"  Found {len(findings)} issue(s):\n")
            for f in findings:
                print(f"  [{f.severity}] {f.file}:{f.line}")
                print(f"    Pattern: {f.pattern} ({f.cwe})")
                print(f"    Code: {f.code}")
                print(f"    {f.description}")
                print()

        print(f"  Mitigations detected:")
        for name, found in mitigations.items():
            status = "YES" if found else "NO"
            print(f"    {name}: {status}")
        print()

    if args.fail_on:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threshold = sev_order[args.fail_on]
        failing = [f for f in findings if sev_order.get(f.severity, 3) <= threshold]
        sys.exit(1 if failing else 0)
    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
