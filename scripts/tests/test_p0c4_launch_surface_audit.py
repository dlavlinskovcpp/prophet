from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("p0c4_launch_surface_audit", ROOT / "scripts/p0c4_launch_surface_audit.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_whole_launch_surface_is_clean():
    result = MODULE.audit()
    assert result["status"] == "PASS", result["findings"]
    assert result["production_generic_signer_reachability"] == 0
    assert result["production_role_selectable_signer_reachability"] == 0
    assert result["production_same_process_a_b_credential_capability"] == 0
    assert result["recovery_same_process_a_b_credential_capability"] == 0
    assert result["localnet_generic_signer_reachability"] == 0
    assert result["coordinator_signer_credentials"] == 0
    assert result["submitter_signer_credentials"] == 0
