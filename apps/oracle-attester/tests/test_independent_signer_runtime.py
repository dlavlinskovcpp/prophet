from dataclasses import replace

import pytest
from solders.keypair import Keypair

from src.independent_signer_runtime import (
    IndependentSignerRuntimeConfigError,
    IndependentSignerTopologyError,
    IndependentSignerServiceConfig,
    canonicalize_journal_path,
    validate_independent_signer_topology,
)


GENESIS = "11" * 32


def _raw(role, key, *, environment="public-devnet", mode="production", topology="OPERATED_2OF2"):
    lower = role.lower()
    return {
        "environment": environment,
        "mode": mode,
        "topology_classification": topology,
        "signer": {"role": role, "signer_id": f"signer-{lower}", "public_key": str(key.pubkey()), "key_version": 1},
        "vault": {
            "address": f"https://vault-{lower}.example", "transit_mount": "transit",
            "key_name": f"notary-{lower}", "token_env": f"SIGNER_{role}_VAULT_TOKEN",
            "admin_domain_id": f"vault-admin-{lower}", "account_or_tenant_id": f"vault-account-{lower}",
            "auth_principal_id": f"vault-principal-{lower}", "timeout_seconds": 10,
        },
        "rpc": {
            "url_env": f"SIGNER_{role}_RPC_URL", "provider_domain_id": f"rpc-provider-{lower}",
            "account_or_project_id": f"rpc-account-{lower}", "credential_principal_id": f"rpc-principal-{lower}",
        },
        "solana": {"expected_genesis_hash": GENESIS, "expected_program_id": "11111111111111111111111111111111"},
        "journal_path": f"/var/lib/prophet/signer-{lower}.sqlite",
        "admission_token_env": f"SIGNER_{role}_ADMISSION_TOKEN",
    }


def _configs():
    return (
        IndependentSignerServiceConfig.from_mapping(_raw("A", Keypair.from_seed(bytes([1]) * 32))),
        IndependentSignerServiceConfig.from_mapping(_raw("B", Keypair.from_seed(bytes([2]) * 32))),
    )


def test_valid_one_signer_configs_and_independent_operated_topology():
    a, b = _configs()
    assert a.signer_role == "A" and b.signer_role == "B"
    assert validate_independent_signer_topology(a, b) == "OPERATED_2OF2_ACCEPTABLE"
    assert a.fingerprint() == IndependentSignerServiceConfig.from_mapping(_raw("A", Keypair.from_seed(bytes([1]) * 32))).fingerprint()
    assert a.fingerprint() != replace(a, vault_key_name="notary-next").fingerprint()
    with pytest.raises(Exception):
        a.signer_id = "changed"


@pytest.mark.parametrize("attribute", (
    "signer_id", "signer_public_key", "vault_key_name", "journal_path", "admission_token_env",
    "vault_auth_principal_id", "vault_admin_domain_id", "vault_account_or_tenant_id",
    "rpc_credential_principal_id", "rpc_provider_domain_id", "rpc_account_or_project_id",
))
def test_operated_topology_rejects_every_required_identity_collision(attribute):
    a, b = _configs()
    with pytest.raises(IndependentSignerTopologyError):
        validate_independent_signer_topology(a, replace(b, **{attribute: getattr(a, attribute)}))


def test_roles_must_be_exactly_a_and_b():
    a, b = _configs()
    with pytest.raises(IndependentSignerTopologyError):
        validate_independent_signer_topology(a, replace(b, signer_role="A"))


def test_topology_rejects_b_plus_b_roles():
    a, b = _configs()
    with pytest.raises(IndependentSignerTopologyError):
        validate_independent_signer_topology(replace(a, signer_role="B"), b)


def test_different_urls_do_not_override_shared_vault_or_rpc_domains():
    a, b = _configs()
    with pytest.raises(IndependentSignerTopologyError):
        validate_independent_signer_topology(a, replace(b, vault_address="https://other-vault.example", vault_admin_domain_id=a.vault_admin_domain_id))
    with pytest.raises(IndependentSignerTopologyError):
        validate_independent_signer_topology(a, replace(b, rpc_url_env="OTHER_RPC_URL", rpc_provider_domain_id=a.rpc_provider_domain_id))


@pytest.mark.parametrize("alias", (
    "/var/lib/prophet/./signer-a.sqlite",
    "/var/lib/prophet/tmp/../signer-a.sqlite",
    "/var/lib/prophet//signer-a.sqlite",
))
def test_operated_topology_rejects_canonical_journal_path_aliases(alias):
    a, b = _configs()
    with pytest.raises(IndependentSignerTopologyError):
        validate_independent_signer_topology(a, replace(b, journal_path=alias))


def test_operated_topology_rejects_existing_symlink_journal_alias(tmp_path):
    real = tmp_path / "real"; real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unsupported: {exc}")
    a, b = _configs()
    a = replace(a, journal_path=str(real / "signer.sqlite"))
    b = replace(b, journal_path=str(alias / "signer.sqlite"))
    assert a.journal_path_identity == b.journal_path_identity
    with pytest.raises(IndependentSignerTopologyError):
        validate_independent_signer_topology(a, b)


def test_distinct_canonical_journal_paths_remain_acceptable_and_production_relative_rejects():
    a, b = _configs()
    assert validate_independent_signer_topology(a, b) == "OPERATED_2OF2_ACCEPTABLE"
    with pytest.raises(IndependentSignerRuntimeConfigError):
        replace(a, journal_path="relative.sqlite")


@pytest.mark.parametrize("path", (None, "", "   ", "journal\x00.sqlite"))
def test_canonical_journal_path_rejects_malformed_values(path):
    with pytest.raises(IndependentSignerRuntimeConfigError):
        canonicalize_journal_path(path, require_absolute=True)


def test_explicit_correlated_localtest_is_functional_only_and_public_devnet_rejects_it():
    first, second = Keypair.from_seed(bytes([1]) * 32), Keypair.from_seed(bytes([2]) * 32)
    a = IndependentSignerServiceConfig.from_mapping(_raw("A", first, environment="localtest", mode="test", topology="FUNCTIONAL_TEST_ONLY"))
    raw_b = _raw("B", second, environment="localtest", mode="test", topology="FUNCTIONAL_TEST_ONLY")
    for field in ("admin_domain_id", "account_or_tenant_id", "auth_principal_id"):
        raw_b["vault"][field] = _raw("A", first, environment="localtest", mode="test", topology="FUNCTIONAL_TEST_ONLY")["vault"][field]
    for field in ("provider_domain_id", "account_or_project_id", "credential_principal_id"):
        raw_b["rpc"][field] = _raw("A", first, environment="localtest", mode="test", topology="FUNCTIONAL_TEST_ONLY")["rpc"][field]
    b = IndependentSignerServiceConfig.from_mapping(raw_b)
    assert validate_independent_signer_topology(a, b) == "FUNCTIONAL_TEST_ONLY"
    with pytest.raises(IndependentSignerRuntimeConfigError):
        IndependentSignerServiceConfig.from_mapping(_raw("A", first, topology="FUNCTIONAL_TEST_ONLY"))


def test_correlated_mainnet_topology_is_rejected():
    first, second = Keypair.from_seed(bytes([1]) * 32), Keypair.from_seed(bytes([2]) * 32)
    a = IndependentSignerServiceConfig.from_mapping(_raw("A", first, environment="mainnet"))
    b = IndependentSignerServiceConfig.from_mapping(_raw("B", second, environment="mainnet"))
    with pytest.raises(IndependentSignerTopologyError):
        validate_independent_signer_topology(a, replace(b, rpc_provider_domain_id=a.rpc_provider_domain_id))


@pytest.mark.parametrize("value", (True, False, 0, -1, "1"))
def test_key_version_is_strict_and_bool_is_rejected(value):
    raw = _raw("A", Keypair.from_seed(bytes([1]) * 32)); raw["signer"]["key_version"] = value
    with pytest.raises(IndependentSignerRuntimeConfigError):
        IndependentSignerServiceConfig.from_mapping(raw)


def test_strict_schema_blocks_inline_secret_and_counterpart_credentials_are_not_required():
    raw = _raw("A", Keypair.from_seed(bytes([1]) * 32)); raw["vault"]["token"] = "secret"
    with pytest.raises(IndependentSignerRuntimeConfigError):
        IndependentSignerServiceConfig.from_mapping(raw)
    a, b = _configs()
    assert "SIGNER_B_VAULT_TOKEN" not in a.__dict__.values()
    assert "SIGNER_B_RPC_URL" not in a.__dict__.values()
    assert "SIGNER_B_ADMISSION_TOKEN" not in a.__dict__.values()
    assert "SIGNER_A_VAULT_TOKEN" not in b.__dict__.values()
    assert "SIGNER_A_RPC_URL" not in b.__dict__.values()
    assert "SIGNER_A_ADMISSION_TOKEN" not in b.__dict__.values()
