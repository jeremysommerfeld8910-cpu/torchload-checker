# torchload-checker

**Scan Python repos for unsafe `torch.load()` and pickle deserialization (CWE-502)**

[![PyPI](https://img.shields.io/pypi/v/torchload-checker)](https://pypi.org/project/torchload-checker/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why

`torch.load()` uses `pickle` under the hood, which can execute arbitrary code during deserialization. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html) — one of the most dangerous vulnerability classes in ML/AI codebases.

PyTorch added `weights_only=True` as a safe default in v2.6, but thousands of repos still use the unsafe pattern. We've found **160+ unsafe deserialization patterns** across major ML projects including GPT-SoVITS, Coqui TTS, EasyOCR, and vllm.

## Install

```bash
pip install torchload-checker
```

## Usage

```bash
# Scan a repository
torchload-checker /path/to/repo

# JSON output for CI/CD
torchload-checker /path/to/repo --json

# SARIF output for GitHub Code Scanning
torchload-checker /path/to/repo --sarif > results.sarif

# Only show HIGH and CRITICAL findings
torchload-checker /path/to/repo --severity HIGH

# Exclude test/example directories
torchload-checker /path/to/repo --exclude-tests

# Summary counts only
torchload-checker /path/to/repo --summary

# Save baseline (track existing findings)
torchload-checker /path/to/repo --save-baseline baseline.json

# Only report NEW findings not in baseline
torchload-checker /path/to/repo --baseline baseline.json

# Version
torchload-checker --version
```

## What It Detects

| Pattern | Severity | Description |
|---------|----------|-------------|
| `torch.load(weights_only=False)` | CRITICAL | Explicit unsafe deserialization |
| `torch.load()` (no weights_only) | HIGH | Defaults to unsafe in PyTorch <2.6 |
| `pickle.load/loads` | HIGH | Direct pickle deserialization |
| `pickle.Unpickler` | HIGH | Manual pickle unpickling |
| `cloudpickle.load/loads` | HIGH | cloudpickle deserialization |
| `dill.load/loads` | HIGH | dill deserialization |
| `joblib.load` | MEDIUM | Uses pickle internally |
| `yaml.load` (unsafe) | HIGH | Without SafeLoader = RCE |
| `shelve.open` | MEDIUM | Uses pickle internally |
| `numpy.load(allow_pickle=True)` | HIGH | numpy pickle deserialization |
| `pandas.read_pickle` | HIGH | Uses pickle internally |
| `marshal.loads` | HIGH | Arbitrary code via bytecode |
| `_pickle.loads/Unpickler` | HIGH | C-accelerated pickle (same risks) |
| `torch.save(user data)` | MEDIUM | User-controlled data in save path |

## Mitigation Detection

torchload-checker also detects when repos use safe alternatives:
- `safetensors` library usage
- `weights_only=True` parameter
- `yaml.SafeLoader` / `yaml.safe_load`

## Baseline Mode (Incremental CI)

Adopt torchload-checker incrementally — prevent new issues without fixing all existing ones:

```bash
# Step 1: Record current findings as baseline
torchload-checker /path/to/repo --save-baseline baseline.json

# Step 2: In CI, only fail on NEW findings
torchload-checker /path/to/repo --baseline baseline.json --severity HIGH
```

## GitHub Action

Use as a reusable action:

```yaml
- uses: jeremysommerfeld8910-cpu/torchload-checker@v0.4.0
  with:
    path: .
    severity: HIGH
    exclude-tests: true
    sarif: true
```

Or with pip install:

```yaml
name: CWE-502 Security Scan
on: [push, pull_request]

jobs:
  torchload-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install torchload-checker
      - run: torchload-checker . --severity HIGH --json > results.json

      # Upload SARIF to GitHub Code Scanning
      - run: torchload-checker . --sarif > results.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/jeremysommerfeld8910-cpu/torchload-checker
    rev: v0.4.0
    hooks:
      - id: torchload-checker
```

## Real-World Findings

Found unsafe patterns in major ML projects:

| Project | Stars | Findings | Severity |
|---------|-------|----------|----------|
| GPT-SoVITS | 55K | 46 | 22 CRITICAL + 24 HIGH |
| huggingface/transformers | 145K | 44 | 7 CRITICAL + 37 HIGH |
| vllm | 72K | 17 | HIGH |
| coqui-ai/TTS | 45K | 24 | HIGH |
| EasyOCR | 29K | 13 | 4 CRITICAL + 9 HIGH |
| GFPGAN | 37K | 8 | HIGH |
| Real-ESRGAN | 34K | 8 | HIGH |

## License

MIT
