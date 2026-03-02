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

import argparse
import json
import os
import re
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List

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
        "regex": r"pickle\.(load|loads)\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "Direct pickle deserialization allows arbitrary code execution"
    },
    {
        "name": "pickle.Unpickler",
        "regex": r"pickle\.Unpickler\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "Pickle Unpickler can execute arbitrary code during deserialization"
    },
    {
        "name": "cloudpickle.load/loads",
        "regex": r"cloudpickle\.(load|loads)\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "desc": "cloudpickle deserialization allows arbitrary code execution"
    },
    {
        "name": "dill.load/loads",
        "regex": r"dill\.(load|loads)\s*\(",
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
        "regex": r"yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*yaml\.SafeLoader)",
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
]

MITIGATIONS = {
    "safetensors": r"(?:from\s+safetensors|import\s+safetensors|\.safetensors)",
    "weights_only_true": r"weights_only\s*=\s*True",
    "safe_loader": r"yaml\.SafeLoader|yaml\.safe_load",
}

SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.tox', '.eggs', 'venv', '.venv', 'env'}

def scan_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            lines = f.readlines()
    except (PermissionError, IsADirectoryError):
        return findings

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('"""') or stripped.startswith("'''"):
            continue
        for pat in PATTERNS:
            if re.search(pat["regex"], line):
                findings.append(Finding(
                    file=filepath,
                    line=i,
                    pattern=pat["name"],
                    code=stripped[:120],
                    severity=pat["severity"],
                    cwe=pat["cwe"],
                    description=pat["desc"]
                ))
    return findings

def scan_repo(repo_path: str, min_severity: str = "LOW") -> List[Finding]:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_sev_val = sev_order.get(min_severity.upper(), 3)

    all_findings = []
    repo = Path(repo_path)

    for py_file in repo.rglob("*.py"):
        if any(skip in py_file.parts for skip in SKIP_DIRS):
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

def main():
    parser = argparse.ArgumentParser(description="Scan repos for unsafe deserialization (CWE-502)")
    parser.add_argument("path", help="Path to repository to scan")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--severity", default="LOW", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity to report (default: LOW)")
    parser.add_argument("--version", action="version", version="torchload-checker 0.1.0")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a directory", file=sys.stderr)
        sys.exit(1)

    findings = scan_repo(args.path, args.severity)
    mitigations = check_mitigations(args.path)

    if args.json:
        output = {
            "repo": args.path,
            "total_findings": len(findings),
            "findings": [asdict(f) for f in findings],
            "mitigations": mitigations
        }
        print(json.dumps(output, indent=2))
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

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
