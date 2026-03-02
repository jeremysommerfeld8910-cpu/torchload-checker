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
        "regex": r"_pickle\.(loads?|Unpickler)\s*\(",
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
    """Check if a line should be skipped (comment, string def, etc.)."""
    if stripped.startswith('#'):
        return True
    if re.match(r'^["\'].*["\'],?\s*$', stripped):
        return True
    if re.match(r'^\s*"(name|regex|desc|description|pattern)":', stripped):
        return True
    return False

def scan_file(filepath: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            lines = f.readlines()
    except (PermissionError, IsADirectoryError):
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
        if exclude_tests and py_file.name.startswith("test_"):
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
                    "version": "0.3.0",
                    "informationUri": "https://github.com/jeremysommerfeld8910-cpu/torchload-checker",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }]
    }

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
    parser.add_argument("--version", action="version", version="torchload-checker 0.3.0")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a directory", file=sys.stderr)
        sys.exit(1)

    exclude = getattr(args, 'exclude_tests', False)
    findings = scan_repo(args.path, args.severity, exclude_tests=exclude)
    mitigations = check_mitigations(args.path)

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

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
