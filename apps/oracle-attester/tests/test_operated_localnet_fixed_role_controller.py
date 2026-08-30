"""Regression contract for the localtest fixed-role smoke controller."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTROLLER = ROOT / "scripts" / "operated_localnet_smoke.py"


def _load():
    spec = importlib.util.spec_from_file_location("operated_localnet_fixed_role", CONTROLLER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_controller_retires_generic_signer_and_legacy_auth_paths():
    source = CONTROLLER.read_text(encoding="utf-8")
    for forbidden in (
        "remote_signer" + "_main",
        "os.environ" + ".copy()",
        "dict(os.environ)",
        "ThresholdResolution" + "Signer",
        "Authorization\": f\"Bear" + "er",
    ):
        assert forbidden not in source
    assert 'f"scripts/localtest_signer_{role.lower()}_worker.py"' in source
    assert 'f"scripts/localtest_signer_{role.lower()}_admission_issuer.py"' in source


def test_controller_uses_explicit_child_environment_and_never_names_private_files():
    source = CONTROLLER.read_text(encoding="utf-8")
    assert "def _child_env" in source
    assert "env=_child_env()" in source
    for private_name in ("signer.seed", "admission-issuer.seed"):
        assert private_name not in source


def test_controller_orchestrates_two_real_fixed_role_workers():
    controller = _load()
    result = controller.run_smoke()
    assert result["status"] == "PASS"
    assert result["environment"] == "localtest"
    assert len(result["acceptance_run_id"]) == 32
    assert result["signer_a"] != result["signer_b"]
    assert result["message_bytes"] == 235
