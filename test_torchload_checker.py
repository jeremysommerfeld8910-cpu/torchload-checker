"""Tests for torchload-checker."""
import tempfile
import os
from torchload_checker import scan_file, scan_repo, check_mitigations, Finding

def _write_temp(content):
    """Write content to a temp .py file and return path."""
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return path


def test_detects_torch_load_weights_only_false():
    path = _write_temp('model = torch.load("model.pt", weights_only=False)')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "weights_only=False" in findings[0].pattern


def test_detects_torch_load_no_weights_only():
    path = _write_temp('model = torch.load("model.pt")')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) >= 1
    assert any(f.severity == "HIGH" for f in findings)


def test_detects_pickle_load():
    path = _write_temp('data = pickle.load(open("data.pkl", "rb"))')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 1
    assert findings[0].pattern == "pickle.load/loads"


def test_detects_yaml_load():
    path = _write_temp('config = yaml.load(open("config.yml"))')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) >= 1
    assert any("yaml" in f.pattern for f in findings)


def test_skips_comments():
    path = _write_temp('# torch.load("model.pt", weights_only=False)')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 0


def test_clean_file_no_findings():
    path = _write_temp('import torch\nmodel = torch.nn.Linear(10, 5)')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 0


def test_scan_repo():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "bad.py"), "w") as f:
            f.write('data = pickle.loads(raw_bytes)\n')
        findings = scan_repo(d)
        assert len(findings) == 1


def test_mitigations_detection():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "safe.py"), "w") as f:
            f.write('from safetensors import safe_open\nmodel = torch.load(f, weights_only=True)\n')
        mits = check_mitigations(d)
        assert mits["safetensors"] is True
        assert mits["weights_only_true"] is True


def test_severity_filter():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "mixed.py"), "w") as f:
            f.write('pickle.load(f)\njoblib.load("model.pkl")\n')
        high_only = scan_repo(d, min_severity="HIGH")
        all_findings = scan_repo(d, min_severity="LOW")
        assert len(high_only) <= len(all_findings)
        assert all(f.severity in ("CRITICAL", "HIGH") for f in high_only)


def test_detects_numpy_load_allow_pickle():
    path = _write_temp('data = np.load("model.npy", allow_pickle=True)')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 1
    assert "numpy" in findings[0].pattern


def test_detects_pandas_read_pickle():
    path = _write_temp('df = pd.read_pickle("data.pkl")')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 1
    assert "pandas" in findings[0].pattern


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
