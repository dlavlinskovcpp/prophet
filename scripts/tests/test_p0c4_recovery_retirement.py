from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_legacy_dual_capability_recovery_entrypoint_is_retired():
    source = (ROOT / "scripts/secure_vault_2of2_smoke.py").read_text(encoding="utf-8")
    assert "ThresholdResolutionSigner" not in source
    assert "VAULT_SIGNER_A_KEY_NAME" not in source
    assert "VAULT_SIGNER_B_KEY_NAME" not in source
    assert "role_local_recovery_required" in source
