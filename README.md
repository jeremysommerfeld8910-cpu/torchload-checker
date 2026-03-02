# torchload-checker

**Scan Python repos for unsafe `torch.load()` and pickle deserialization (CWE-502)**

[![PyPI](https://img.shields.io/pypi/v/torchload-checker)](https://pypi.org/project/torchload-checker/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why

`torch.load()` uses `pickle` under the hood, which can execute arbitrary code during deserialization. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html) — one of the most dangerous vulnerability classes in ML/AI codebases.

PyTorch added `weights_only=True` as a safe default in v2.6, but thousands of repos still use the unsafe pattern. We've found **128+ unsafe deserialization patterns** across major ML projects.

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

# Only show HIGH and CRITICAL findings
torchload-checker /path/to/repo --severity HIGH

# Exclude test/example directories
torchload-checker /path/to/repo --exclude-tests

# Summary counts only
torchload-checker /path/to/repo --summary

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

## Mitigation Detection

torchload-checker also detects when repos use safe alternatives:
- `safetensors` library usage
- `weights_only=True` parameter
- `yaml.SafeLoader` / `yaml.safe_load`

## GitHub Action

Add to `.github/workflows/scan.yml`:

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
```

## Real-World Findings

Found unsafe patterns in major ML projects:

| Project | Findings | Severity |
|---------|----------|----------|
| vllm | 41 | HIGH-CRITICAL |
| mlflow | 39 | HIGH |
| BentoML | 34 | HIGH |
| V-JEPA (Meta) | 11 | HIGH |
| I-JEPA (Meta) | 3 | HIGH |

## License

MIT
