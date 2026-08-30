import os

import pytest
from solders.keypair import Keypair

from src.fixed_role_signer import FixedRoleSignerStartupError, fixed_role_child_environment
from src.signer_a_main import load_signer_a_config
from src.signer_b_main import load_signer_b_config


def _config(role: str):
    return {
        "environment": "public-devnet", "mode": "production", "topology_classification": "OPERATED_2OF2",
        "signer": {"role": role, "signer_id": f"signer-{role.lower()}", "public_key": str(Keypair.from_seed(bytes([ord(role)]) * 32).pubkey()), "key_version": 1},
        "vault": {"address": "https://vault.example", "transit_mount": "transit", "key_name": f"key-{role.lower()}", "token_env": f"SIGNER_{role}_VAULT_TOKEN", "admin_domain_id": f"vault-{role}", "account_or_tenant_id": f"tenant-{role}", "auth_principal_id": f"principal-{role}", "timeout_seconds": 10},
        "rpc": {"url_env": f"SIGNER_{role}_RPC_URL", "provider_domain_id": f"rpc-{role}", "account_or_project_id": f"account-{role}", "credential_principal_id": f"rpc-principal-{role}"},
        "solana": {"expected_genesis_hash": "11" * 32, "expected_program_id": "11111111111111111111111111111111"},
        "journal_path": f"/var/lib/prophet/signer-{role.lower()}.sqlite", "admission_token_env": f"SIGNER_{role}_ADMISSION_TOKEN",
    }


@pytest.mark.parametrize("loader,role", [(load_signer_a_config, "A"), (load_signer_b_config, "B")])
def test_fixed_role_entry_accepts_only_its_own_role(loader, role):
    assert loader(_config(role)).signer_role == role
    peer = "B" if role == "A" else "A"
    with pytest.raises(FixedRoleSignerStartupError, match="role_override"):
        loader(_config(peer))


@pytest.mark.parametrize("loader,role", [(load_signer_a_config, "A"), (load_signer_b_config, "B")])
def test_fixed_role_parser_rejects_peer_credential_before_lookup(loader, role):
    value = _config(role)
    peer = "B" if role == "A" else "A"
    value["vault"]["token_env"] = f"SIGNER_{peer}_VAULT_TOKEN"
    with pytest.raises(Exception, match="opposite_role_reference"):
        loader(value)


@pytest.mark.parametrize("loader,role", [(load_signer_a_config, "A"), (load_signer_b_config, "B")])
def test_child_environment_is_explicitly_role_local(monkeypatch, loader, role):
    peer = "B" if role == "A" else "A"
    for key in (f"SIGNER_{role}_VAULT_TOKEN", f"SIGNER_{role}_ADMISSION_TOKEN", f"SIGNER_{role}_RPC_URL", f"SIGNER_{peer}_VAULT_TOKEN"):
        monkeypatch.setenv(key, key.lower())
    child = fixed_role_child_environment(loader(_config(role)))
    assert f"SIGNER_{role}_VAULT_TOKEN" in child
    assert f"SIGNER_{peer}_VAULT_TOKEN" not in child
    assert set(child) <= {"PATH", "LANG", "LC_ALL", f"SIGNER_{role}_VAULT_TOKEN", f"SIGNER_{role}_ADMISSION_TOKEN", f"SIGNER_{role}_RPC_URL"}
