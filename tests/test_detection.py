"""
test_detection.py -- unit tests for the SE6013 CVE-2026-4372 detection + defence layers.

Run from the repo root:
    pytest -q

These tests exercise the static scanner and the defensive loader's control logic.
They never load a model and never execute fixture content.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection import config_scanner
from detection import audit_dependencies
from defence.safe_load import safe_from_pretrained, UnsafeModelLoad

FIXTURES = Path(__file__).parent / "fixtures"
BENIGN = FIXTURES / "benign"
FLAGGED = FIXTURES / "flagged"


# --------------------------------------------------------------------------- #
# Config scanner
# --------------------------------------------------------------------------- #

def test_benign_config_has_no_findings():
    findings = config_scanner.scan_repo(BENIGN)
    assert findings == [], f"benign config should be clean, got: {[f.human() for f in findings]}"


def test_flagged_config_is_detected():
    findings = config_scanner.scan_repo(FLAGGED)
    assert findings, "flagged config should produce findings"


def test_flagged_config_catches_cve_field():
    findings = config_scanner.scan_config_file(FLAGGED / "config.json")
    keys = {f.location for f in findings if f.kind == "key"}
    assert "_attn_implementation_internal" in keys
    assert any(k.startswith("auto_map") for k in keys)


def test_flagged_config_has_high_severity():
    findings = config_scanner.scan_config_file(FLAGGED / "config.json")
    high = config_scanner.filter_by_severity(findings, "high")
    assert high, "expected at least one high-severity finding"


def test_severity_filter_monotonic():
    findings = config_scanner.scan_config_file(FLAGGED / "config.json")
    low = config_scanner.filter_by_severity(findings, "low")
    med = config_scanner.filter_by_severity(findings, "medium")
    high = config_scanner.filter_by_severity(findings, "high")
    assert len(low) >= len(med) >= len(high)


def test_scanner_handles_malformed_json(tmp_path):
    bad = tmp_path / "config.json"
    bad.write_text("{ not valid json ", encoding="utf-8")
    findings = config_scanner.scan_config_file(bad)
    assert any(f.kind == "parse_error" for f in findings)


def test_scanner_does_not_import_transformers():
    # Scanning must not pull in transformers (it only parses JSON).
    before = set(sys.modules)
    config_scanner.scan_repo(FLAGGED)
    newly = set(sys.modules) - before
    assert "transformers" not in newly


# --------------------------------------------------------------------------- #
# Dependency audit
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ver,vulnerable", [
    ("5.2.0", True),
    ("5.2.9", True),
    ("4.57.3", True),
    ("5.3.0", False),
    ("5.3.1", False),
    ("5.13.1", False),
    ("6.0.0", False),
])
def test_version_comparison(ver, vulnerable):
    assert audit_dependencies._lt_fixed(ver) is vulnerable


def test_requirements_ceiling_pin_permits_vulnerable(tmp_path):
    # "<5.3.0" permits ONLY versions below the fix -> must be flagged.
    req = tmp_path / "requirements.txt"
    req.write_text("torch\ntransformers<5.3.0\nhuggingface_hub\n", encoding="utf-8")
    spec = audit_dependencies.spec_from_requirements(req)
    assert spec == "<5.3.0"
    assert audit_dependencies.permits_vulnerable(spec) is True


def test_requirements_secure_pin_excludes_vulnerable(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("transformers==5.3.1\n", encoding="utf-8")
    spec = audit_dependencies.spec_from_requirements(req)
    assert spec == "==5.3.1"
    assert audit_dependencies.permits_vulnerable(spec) is False


def test_requirements_floor_with_ceiling_is_safe(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("transformers[all]>=5.3.0,<6\n", encoding="utf-8")
    spec = audit_dependencies.spec_from_requirements(req)
    assert spec == ">=5.3.0,<6"
    assert audit_dependencies.permits_vulnerable(spec) is False


def test_requirements_unpinned_permits_vulnerable(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("transformers\n", encoding="utf-8")
    spec = audit_dependencies.spec_from_requirements(req)
    assert spec == ""
    assert audit_dependencies.permits_vulnerable(spec) is True


def test_requirements_transformers_absent(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("torch\nnumpy\n", encoding="utf-8")
    assert audit_dependencies.spec_from_requirements(req) is None


# --------------------------------------------------------------------------- #
# Defence wrapper -- control logic (no model is ever loaded)
# --------------------------------------------------------------------------- #

def _loader_spy():
    calls = {}
    def loader(model_id, **kwargs):
        calls["model_id"] = model_id
        calls["kwargs"] = kwargs
        return "LOADED"
    return loader, calls


def test_safe_load_blocks_on_flagged_config(monkeypatch):
    # Pretend the environment is patched so the version gate passes and the scan
    # is what blocks.
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    loader, _ = _loader_spy()
    with pytest.raises(UnsafeModelLoad):
        safe_from_pretrained(str(FLAGGED), loader=loader, local_files_only=True)


def test_safe_load_allows_benign_config(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    loader, calls = _loader_spy()
    result = safe_from_pretrained(str(BENIGN), loader=loader, local_files_only=True)
    assert result == "LOADED"
    # Control 3: trust_remote_code is forced False regardless of caller intent.
    assert calls["kwargs"]["trust_remote_code"] is False


def test_safe_load_forces_trust_remote_code_false(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    loader, calls = _loader_spy()
    safe_from_pretrained(str(BENIGN), loader=loader, local_files_only=True,
                         trust_remote_code=True)
    assert calls["kwargs"]["trust_remote_code"] is False


def test_safe_load_blocks_vulnerable_env(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.2.0")
    loader, _ = _loader_spy()
    with pytest.raises(UnsafeModelLoad):
        safe_from_pretrained(str(BENIGN), loader=loader, local_files_only=True)


def test_safe_load_accept_findings_override(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    loader, calls = _loader_spy()
    result = safe_from_pretrained(str(FLAGGED), loader=loader, local_files_only=True,
                                  accept_findings=True)
    assert result == "LOADED"


# --------------------------------------------------------------------------- #
# Attention-implementation values (the Hub-kernel path of CVE-2026-4372)
# --------------------------------------------------------------------------- #

def _write_config(dirpath: Path, cfg: dict) -> Path:
    import json
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return dirpath


# Inert placeholders shaped like Hub kernel references; no such repos are fetched.
HUB_KERNEL_VALUES = [
    "inert-placeholder/no-such-kernel",
    "inert-placeholder/no-such-kernel@main",
    "inert-placeholder/no-such-kernel:no_such_fn",
    {"text_config": "inert-placeholder/no-such-kernel"},
    "not_a_builtin_impl",
]


@pytest.mark.parametrize("value", HUB_KERNEL_VALUES)
@pytest.mark.parametrize("key", ["attn_implementation", "_attn_implementation_internal"])
def test_scanner_flags_non_builtin_attn_value_high(tmp_path, key, value):
    _write_config(tmp_path, {"model_type": "gpt2", key: value})
    high = config_scanner.filter_by_severity(config_scanner.scan_repo(tmp_path), "high")
    assert any(f.kind == "attn_value" for f in high)


@pytest.mark.parametrize("value", ["eager", "sdpa", "flash_attention_2", None,
                                   {"text_config": "sdpa", "vision_config": "eager"}])
def test_scanner_allows_builtin_attn_value(tmp_path, value):
    _write_config(tmp_path, {"model_type": "gpt2", "attn_implementation": value})
    assert config_scanner.scan_repo(tmp_path) == []


def test_scanner_flags_nested_subconfig_attn_value(tmp_path):
    _write_config(tmp_path, {"model_type": "llava",
                             "text_config": {"attn_implementation": "inert-placeholder/x"}})
    findings = config_scanner.scan_repo(tmp_path)
    assert any(f.kind == "attn_value" and f.location == "text_config.attn_implementation"
               for f in findings)


# --------------------------------------------------------------------------- #
# Defence wrapper -- defence-in-depth on an unpatched install
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", HUB_KERNEL_VALUES)
def test_safe_load_scan_blocks_hub_kernel_in_vulnerable_env(tmp_path, monkeypatch, value):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.2.0")
    monkeypatch.setattr("defence.safe_load._kernels_installed", lambda: False)
    _write_config(tmp_path, {"model_type": "gpt2", "attn_implementation": value})
    loader, calls = _loader_spy()
    with pytest.raises(UnsafeModelLoad, match="config scan"):
        safe_from_pretrained(str(tmp_path), loader=loader, local_files_only=True,
                             allow_vulnerable_env=True)
    assert calls == {}


def test_safe_load_kernels_gate_in_vulnerable_env(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.2.0")
    monkeypatch.setattr("defence.safe_load._kernels_installed", lambda: True)
    loader, _ = _loader_spy()
    with pytest.raises(UnsafeModelLoad, match="kernels"):
        safe_from_pretrained(str(BENIGN), loader=loader, local_files_only=True,
                             allow_vulnerable_env=True)


def test_safe_load_kernels_gate_ignored_when_patched(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    monkeypatch.setattr("defence.safe_load._kernels_installed", lambda: True)
    loader, _ = _loader_spy()
    assert safe_from_pretrained(str(BENIGN), loader=loader, local_files_only=True) == "LOADED"


def test_safe_load_rejects_config_kwarg(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    loader, _ = _loader_spy()
    with pytest.raises(UnsafeModelLoad, match="config="):
        safe_from_pretrained(str(BENIGN), loader=loader, local_files_only=True,
                             config=object())


def test_safe_load_rejects_file_path(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    loader, _ = _loader_spy()
    with pytest.raises(UnsafeModelLoad, match="is a file"):
        safe_from_pretrained(str(BENIGN / "config.json"), loader=loader)


def test_default_loader_rejects_version_mismatch(monkeypatch):
    import types
    fake = types.ModuleType("transformers")
    fake.__version__ = "5.2.0"
    monkeypatch.setitem(sys.modules, "transformers", fake)
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    from defence.safe_load import _default_loader
    with pytest.raises(UnsafeModelLoad, match="does not match"):
        _default_loader(allow_vulnerable_env=False)


# --------------------------------------------------------------------------- #
# Defence wrapper -- Hub repos are scanned and loaded at one pinned commit
# --------------------------------------------------------------------------- #

PINNED_SHA = "0123456789abcdef0123456789abcdef01234567"


def _fake_hub(monkeypatch, files: dict[str, str]):
    """Install a fake huggingface_hub serving `files` at PINNED_SHA. Records calls."""
    import types
    log = {"downloads": [], "info_revision": "unset"}

    class Sibling:
        def __init__(self, name):
            self.rfilename = name

    class HfApi:
        def model_info(self, repo_id, revision=None):
            log["info_revision"] = revision
            return types.SimpleNamespace(sha=PINNED_SHA,
                                         siblings=[Sibling(n) for n in files])

    def hf_hub_download(repo_id, filename, revision, local_dir):
        log["downloads"].append((filename, revision))
        out = Path(local_dir) / filename
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(files[filename], encoding="utf-8")
        return str(out)

    mod = types.ModuleType("huggingface_hub")
    mod.HfApi, mod.hf_hub_download = HfApi, hf_hub_download
    monkeypatch.setitem(sys.modules, "huggingface_hub", mod)
    return log


def test_safe_load_hub_pins_commit_for_scan_and_load(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    benign = (BENIGN / "config.json").read_text(encoding="utf-8")
    log = _fake_hub(monkeypatch, {"config.json": benign, "model.safetensors": "",
                                  "generation_config.json": "{}"})
    loader, calls = _loader_spy()
    safe_from_pretrained("inert-placeholder/model", loader=loader, revision="main")
    assert log["info_revision"] == "main"
    assert sorted(log["downloads"]) == [("config.json", PINNED_SHA),
                                        ("generation_config.json", PINNED_SHA)]
    assert calls["kwargs"]["revision"] == PINNED_SHA


def test_safe_load_hub_scans_subfolder_configs(monkeypatch):
    monkeypatch.setattr("defence.safe_load.installed_version", lambda: "5.3.1")
    benign = (BENIGN / "config.json").read_text(encoding="utf-8")
    bad = '{"attn_implementation": "inert-placeholder/no-such-kernel"}'
    _fake_hub(monkeypatch, {"config.json": benign, "sub/config.json": bad})
    loader, calls = _loader_spy()
    with pytest.raises(UnsafeModelLoad, match="attn_value"):
        safe_from_pretrained("inert-placeholder/model", loader=loader, subfolder="sub")
    assert calls == {}
