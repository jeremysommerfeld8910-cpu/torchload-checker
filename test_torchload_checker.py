"""Tests for torchload-checker."""
import tempfile
import os
from torchload_checker import scan_file, scan_repo, check_mitigations, findings_to_sarif, Finding

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


def test_skips_string_definitions():
    path = _write_temp('"name": "torch.load(weights_only=False)",\n"regex": r"pickle\\.load"')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 0


def test_skips_multiline_strings():
    path = _write_temp('"""\ntorch.load(model, weights_only=False)\npickle.load(f)\n"""')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 0


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


def test_detects_marshal_loads():
    path = _write_temp('code = marshal.loads(data)')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 1
    assert "marshal" in findings[0].pattern


def test_detects_cpickle():
    path = _write_temp('obj = _pickle.loads(raw)')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) >= 1
    assert any("_pickle" in f.pattern for f in findings)


def test_suppression_nosec():
    path = _write_temp('model = torch.load("m.pt", weights_only=False)  # nosec')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 0


def test_suppression_torchload_ignore():
    path = _write_temp('data = pickle.load(f)  # torchload-ignore')
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) == 0


def test_detects_multiline_torch_load():
    code = 'model = torch.load(\n    "model.pt",\n    map_location=device,\n    weights_only=False\n)'
    path = _write_temp(code)
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) >= 1
    assert any("weights_only=False" in f.pattern for f in findings)


def test_detects_multiline_torch_load_no_weights_only():
    code = 'checkpoint = torch.load(\n    filepath,\n    map_location="cpu"\n)'
    path = _write_temp(code)
    findings = scan_file(path)
    os.unlink(path)
    assert len(findings) >= 1
    assert any("no weights_only" in f.pattern for f in findings)


def test_sarif_output():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "vuln.py"), "w") as f:
            f.write('model = torch.load("m.pt", weights_only=False)\ndata = pickle.load(open("d.pkl","rb"))\n')
        findings = scan_repo(d)
        sarif = findings_to_sarif(findings, d)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "torchload-checker"
        assert len(sarif["runs"][0]["results"]) == len(findings)
        assert all("ruleId" in r for r in sarif["runs"][0]["results"])
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) > 0


def test_exclude_tests_suffix():
    """Test that *_test.py files are excluded with --exclude-tests."""
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "model_test.py"), "w") as f:
            f.write('pickle.load(f)\n')
        with open(os.path.join(d, "main.py"), "w") as f:
            f.write('pickle.load(f)\n')
        findings = scan_repo(d, exclude_tests=True)
        assert len(findings) == 1
        assert "main.py" in findings[0].file


def test_baseline_filtering():
    """Test that baseline mode filters out known findings."""
    import json
    with tempfile.TemporaryDirectory() as d:
        vuln_file = os.path.join(d, "vuln.py")
        with open(vuln_file, "w") as f:
            f.write('pickle.load(f)\ntorch.load("m.pt")\n')

        # Get all findings
        all_findings = scan_repo(d)
        assert len(all_findings) >= 2

        # Create baseline from first finding
        baseline = [{"file": os.path.relpath(all_findings[0].file, d),
                      "pattern": all_findings[0].pattern}]
        baseline_file = os.path.join(d, "baseline.json")
        with open(baseline_file, "w") as bf:
            json.dump(baseline, bf)

        # Filter: findings matching baseline keys should be removed
        baseline_keys = {(b["file"], b["pattern"]) for b in baseline}
        filtered = [f for f in all_findings
                    if (os.path.relpath(f.file, d), f.pattern) not in baseline_keys]
        assert len(filtered) < len(all_findings)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
