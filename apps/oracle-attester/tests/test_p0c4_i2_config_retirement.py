import pytest
from solders.keypair import Keypair

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.secure_settlement_runtime import (
    SecureSettlementRuntimeError,
    load_secure_auth_tokens,
    load_secure_settlement_runtime,
    reject_legacy_secure_settlement_config,
)
from src.independent_signer_runtime import (
    IndependentSignerRuntimeConfigError,
    IndependentSignerServiceConfig,
)
from scripts.validate_operated_config import legacy_signer_secret_errors


def _role_local_config(role: str):
    return {
        "environment": "public-devnet", "mode": "production", "topology_classification": "OPERATED_2OF2",
        "signer": {"role": role, "signer_id": f"signer-{role.lower()}", "public_key": str(Keypair.from_seed(bytes([ord(role)]) * 32).pubkey()), "key_version": 1},
        "vault": {"address": "https://vault.example", "transit_mount": "transit", "key_name": f"key-{role.lower()}", "token_env": f"SIGNER_{role}_VAULT_TOKEN", "admin_domain_id": "vault-admin", "account_or_tenant_id": "vault-account", "auth_principal_id": "vault-principal", "timeout_seconds": 10},
        "rpc": {"url_env": f"SIGNER_{role}_RPC_URL", "provider_domain_id": "rpc-provider", "account_or_project_id": "rpc-account", "credential_principal_id": "rpc-principal"},
        "solana": {"expected_genesis_hash": "11" * 32, "expected_program_id": "11111111111111111111111111111111"},
        "journal_path": f"/var/lib/prophet/signer-{role.lower()}.sqlite", "admission_token_env": f"SIGNER_{role}_ADMISSION_TOKEN",
    }


@pytest.mark.parametrize(
    "policy",
    [
        {"signer_a_vault_token_env": "VAULT_A_TOKEN"},
        {"signer_b_vault_token_env": "VAULT_B_TOKEN"},
        {
            "signer_a_vault_token_env": "VAULT_A_TOKEN",
            "signer_b_vault_token_env": "VAULT_B_TOKEN",
        },
    ],
)
def test_legacy_dual_token_fields_are_rejected_without_secret_resolution(policy):
    with pytest.raises(SecureSettlementRuntimeError, match="legacy_dual_token_config_retired"):
        reject_legacy_secure_settlement_config({"secure_settlement": policy})


@pytest.mark.parametrize("loader", [load_secure_settlement_runtime, load_secure_auth_tokens])
def test_legacy_runtime_loaders_are_unconditionally_retired(loader):
    with pytest.raises(SecureSettlementRuntimeError, match="legacy_secure_settlement_runtime_retired"):
        loader("ignored")


@pytest.mark.parametrize("role", ["A", "B"])
def test_role_local_signer_config_rejects_the_opposite_role_token(role):
    value = _role_local_config(role)
    peer = "B" if role == "A" else "A"
    value["vault"]["token_env"] = f"SIGNER_{peer}_VAULT_TOKEN"
    with pytest.raises(IndependentSignerRuntimeConfigError, match="opposite_role_reference"):
        IndependentSignerServiceConfig.from_mapping(value)


@pytest.mark.parametrize("field", ["token_env_b", "token_env_a"])
def test_role_local_signer_config_rejects_both_role_token_fields(field):
    value = _role_local_config("A")
    value["vault"][field] = "SIGNER_B_VAULT_TOKEN"
    with pytest.raises(IndependentSignerRuntimeConfigError, match="vault_unknown_or_missing_fields"):
        IndependentSignerServiceConfig.from_mapping(value)


def test_operated_detector_rejects_a_and_b_credential_references_in_one_service():
    errors = legacy_signer_secret_errors(
        "PROPHET_VAULT_SIGNER_A_TOKEN=one\nPROPHET_VAULT_SIGNER_B_TOKEN=two\n",
        location="test-service",
    )
    assert len(errors) == 2


@pytest.mark.parametrize("credential", ["PROPHET_VAULT_SIGNER_A_TOKEN", "PROPHET_VAULT_SIGNER_B_TOKEN"])
def test_operated_detector_rejects_any_signer_credential_in_coordinator(credential):
    errors = legacy_signer_secret_errors(credential, location="coordinator", coordinator=True)
    assert errors and "coordinator" in errors[0]
