from dataclasses import replace
import os

import pytest
from solders.keypair import Keypair

from src.independent_signer_deployment import (
    IndependentSignerDeploymentAcceptanceError,
    IndependentSignerDeploymentManifest,
    IndependentSignerDeploymentManifestError,
    validate_operated_signer_deployment,
)
from src.independent_signer_runtime import IndependentSignerServiceConfig


GENESIS = "11" * 32


def _config_raw(role, key, *, environment="public-devnet", mode="production", topology="OPERATED_2OF2"):
    lower = role.lower()
    return {
        "environment": environment, "mode": mode, "topology_classification": topology,
        "signer": {"role": role, "signer_id": f"signer-{lower}", "public_key": str(key.pubkey()), "key_version": 1},
        "vault": {"address": f"https://vault-{lower}.example", "transit_mount": "transit", "key_name": f"notary-{lower}", "token_env": f"SIGNER_{role}_VAULT_TOKEN", "admin_domain_id": f"vault-admin-{lower}", "account_or_tenant_id": f"vault-account-{lower}", "auth_principal_id": f"vault-principal-{lower}", "timeout_seconds": 10},
        "rpc": {"url_env": f"SIGNER_{role}_RPC_URL", "provider_domain_id": f"rpc-provider-{lower}", "account_or_project_id": f"rpc-account-{lower}", "credential_principal_id": f"rpc-principal-{lower}"},
        "solana": {"expected_genesis_hash": GENESIS, "expected_program_id": "11111111111111111111111111111111"},
        "journal_path": f"/var/lib/prophet/signer-{lower}.sqlite", "admission_token_env": f"SIGNER_{role}_ADMISSION_TOKEN",
    }


def _configs(*, environment="public-devnet", mode="production", topology="OPERATED_2OF2"):
    return (
        IndependentSignerServiceConfig.from_mapping(_config_raw("A", Keypair.from_seed(bytes([1]) * 32), environment=environment, mode=mode, topology=topology)),
        IndependentSignerServiceConfig.from_mapping(_config_raw("B", Keypair.from_seed(bytes([2]) * 32), environment=environment, mode=mode, topology=topology)),
    )


def _manifest_mapping(config, *, suffix=None):
    suffix = suffix or config.signer_role.lower()
    return {
        "service_config_fingerprint": config.fingerprint(), "signer_role": config.signer_role,
        "signer_id": config.signer_id, "signer_public_key": config.signer_public_key,
        "deployment_environment": config.environment, "deployment_host_id": f"host-{suffix}",
        "runtime_principal_id": f"principal-{suffix}", "runtime_admin_domain_id": f"admin-{suffix}",
        "service_instance_id": f"instance-{suffix}", "listen_scheme": "http",
        "externally_exposed_scheme": "https", "tls_termination_domain_id": f"tls-{suffix}",
        "server_worker_count": 1, "execution_concurrency_limit": 1, "reload_enabled": False,
        "journal_storage_domain_id": f"journal-{suffix}", "audit_domain_id": f"audit-{suffix}",
    }


def _pair(*, environment="public-devnet", mode="production", topology="OPERATED_2OF2"):
    a, b = _configs(environment=environment, mode=mode, topology=topology)
    return a, b, IndependentSignerDeploymentManifest.from_mapping(_manifest_mapping(a)), IndependentSignerDeploymentManifest.from_mapping(_manifest_mapping(b))


def _matching_manifest(config):
    manifest = IndependentSignerDeploymentManifest.from_mapping(_manifest_mapping(config))
    assert manifest.service_config_fingerprint == config.fingerprint()
    assert manifest.signer_role == config.signer_role
    assert manifest.signer_id == config.signer_id
    assert manifest.signer_public_key == config.signer_public_key
    assert manifest.deployment_environment == config.environment
    return manifest


def test_operated_public_devnet_and_mainnet_pairs_accept_with_deterministic_vectors():
    a, b, ma, mb = _pair()
    result = validate_operated_signer_deployment(a, b, ma, mb)
    assert result.classification == "OPERATED_2OF2_ACCEPTABLE"
    assert ma.fingerprint() == "f31f7d583c9b8bbfe254bab8777996792f264cad7c00300ccc6fffdb52ede1ec"
    assert mb.fingerprint() == "a42e81e9ddddb8cd1ca41a4c19b030050b8bbd8937a00e0b68ea65a93772da63"
    mainnet = _pair(environment="mainnet")
    assert validate_operated_signer_deployment(*mainnet).environment == "mainnet"
    with pytest.raises(Exception):
        ma.deployment_host_id = "changed"


def test_manifest_mapping_is_strict_and_fingerprint_is_order_independent():
    a, _, ma, _ = _pair()
    row = _manifest_mapping(a)
    assert ma.fingerprint() == IndependentSignerDeploymentManifest.from_mapping(dict(reversed(tuple(row.items())))).fingerprint()
    for candidate in ({**row, "unknown": "x"}, {key: value for key, value in row.items() if key != "audit_domain_id"}):
        with pytest.raises(IndependentSignerDeploymentManifestError):
            IndependentSignerDeploymentManifest.from_mapping(candidate)
    for value in (True, False, 0, -1, 1.0, "1", None):
        candidate = dict(row); candidate["execution_concurrency_limit"] = value
        with pytest.raises(IndependentSignerDeploymentManifestError):
            IndependentSignerDeploymentManifest.from_mapping(candidate)
    for field in ("execution_concurrency_limit", "server_worker_count", "deployment_host_id"):
        candidate = {key: value for key, value in row.items() if key != field}
        with pytest.raises(IndependentSignerDeploymentManifestError):
            IndependentSignerDeploymentManifest.from_mapping(candidate)


@pytest.mark.parametrize("field, value", (
    ("deployment_host_id", ""),
    ("runtime_principal_id", " leading"),
    ("journal_storage_domain_id", "domain with spaces"),
    ("reload_enabled", 0),
))
def test_manifest_rejects_empty_or_coercive_security_fields(field, value):
    a, _, _, _ = _pair()
    row = _manifest_mapping(a); row[field] = value
    with pytest.raises(IndependentSignerDeploymentManifestError):
        IndependentSignerDeploymentManifest.from_mapping(row)


@pytest.mark.parametrize("attribute", (
    "deployment_host_id", "runtime_principal_id", "runtime_admin_domain_id", "service_instance_id",
    "journal_storage_domain_id", "audit_domain_id", "tls_termination_domain_id",
))
def test_operated_pair_rejects_every_manifest_failure_domain_collision(attribute):
    a, b, ma, mb = _pair()
    with pytest.raises(IndependentSignerDeploymentAcceptanceError):
        validate_operated_signer_deployment(a, b, ma, replace(mb, **{attribute: getattr(ma, attribute)}))


@pytest.mark.parametrize("attribute", ("server_worker_count", "execution_concurrency_limit"))
@pytest.mark.parametrize("value", (0, -1, 1.0, True, False, "1", None))
def test_manifest_rejects_malformed_worker_and_concurrency_limits(attribute, value):
    a, _, ma, _ = _pair()
    row = _manifest_mapping(a); row[attribute] = value
    with pytest.raises(IndependentSignerDeploymentManifestError):
        IndependentSignerDeploymentManifest.from_mapping(row)


@pytest.mark.parametrize("attribute", ("server_worker_count", "execution_concurrency_limit"))
@pytest.mark.parametrize("value", (2, 4))
def test_positive_non_operated_process_settings_are_representable_but_rejected_by_acceptance(attribute, value):
    a, b, ma, mb = _pair()
    changed = replace(ma, **{attribute: value})
    assert getattr(changed, attribute) == value
    with pytest.raises(IndependentSignerDeploymentAcceptanceError):
        validate_operated_signer_deployment(a, b, changed, mb)


@pytest.mark.parametrize("environment", ("public-devnet", "mainnet"))
def test_manifest_rejects_reload_and_production_insecure_or_missing_tls(environment):
    a, b, ma, mb = _pair(environment=environment)
    row = _manifest_mapping(a); row["reload_enabled"] = True
    with pytest.raises(IndependentSignerDeploymentManifestError):
        IndependentSignerDeploymentManifest.from_mapping(row)
    for attribute, value in (("externally_exposed_scheme", "http"), ("tls_termination_domain_id", "")):
        row = _manifest_mapping(a); row[attribute] = value
        candidate = IndependentSignerDeploymentManifest.from_mapping(row) if value else None
        if candidate is None:
            with pytest.raises(IndependentSignerDeploymentManifestError):
                IndependentSignerDeploymentManifest.from_mapping(row)
        else:
            with pytest.raises(IndependentSignerDeploymentAcceptanceError):
                validate_operated_signer_deployment(a, b, candidate, mb)


@pytest.mark.parametrize("attribute", ("service_config_fingerprint", "signer_role", "signer_id", "signer_public_key", "deployment_environment"))
def test_manifest_must_bind_exactly_to_frozen_service_config(attribute):
    a, b, ma, mb = _pair()
    values = {
        "service_config_fingerprint": "0" * 64, "signer_role": "B", "signer_id": "other-signer",
        "signer_public_key": str(Keypair.from_seed(bytes([9]) * 32).pubkey()), "deployment_environment": "mainnet",
    }
    changed = replace(ma, **{attribute: values[attribute]})
    with pytest.raises(IndependentSignerDeploymentAcceptanceError):
        validate_operated_signer_deployment(a, b, changed, mb)


@pytest.mark.parametrize("environment, mode, topology", (
    ("localtest", "test", "FUNCTIONAL_TEST_ONLY"),
    ("public-devnet", "test", "OPERATED_2OF2"),
))
def test_non_operated_or_non_production_pairs_never_accept(environment, mode, topology):
    a, b, ma, mb = _pair(environment=environment, mode=mode, topology=topology)
    with pytest.raises(IndependentSignerDeploymentAcceptanceError):
        validate_operated_signer_deployment(a, b, ma, mb)


@pytest.mark.parametrize("environment_a, environment_b", (
    ("public-devnet", "mainnet"),
    ("mainnet", "public-devnet"),
))
def test_composed_acceptance_rejects_mixed_environment_in_both_signer_orders(environment_a, environment_b):
    a, _ = _configs(environment=environment_a)
    _, b = _configs(environment=environment_b)
    ma, mb = _matching_manifest(a), _matching_manifest(b)
    with pytest.raises(IndependentSignerDeploymentAcceptanceError, match="p0c3a_topology_rejected"):
        validate_operated_signer_deployment(a, b, ma, mb)


@pytest.mark.parametrize("mode_a, mode_b", (("production", "test"), ("test", "production")))
def test_composed_acceptance_rejects_mixed_mode_in_both_signer_orders(mode_a, mode_b):
    a, b = _configs()
    a, b = replace(a, mode=mode_a), replace(b, mode=mode_b)
    ma, mb = _matching_manifest(a), _matching_manifest(b)
    with pytest.raises(IndependentSignerDeploymentAcceptanceError, match="p0c3a_topology_rejected"):
        validate_operated_signer_deployment(a, b, ma, mb)


@pytest.mark.parametrize("attribute", ("vault_token_env", "admission_token_env", "rpc_url_env"))
def test_distinct_secret_reference_names_remain_required(attribute):
    a, b, ma, mb = _pair()
    changed_config = replace(b, **{attribute: getattr(a, attribute)})
    changed_manifest = IndependentSignerDeploymentManifest.from_mapping(_manifest_mapping(changed_config))
    with pytest.raises(IndependentSignerDeploymentAcceptanceError):
        validate_operated_signer_deployment(a, changed_config, ma, changed_manifest)


@pytest.mark.parametrize("attribute", (
    "signer_public_key", "vault_key_name", "admission_token_env", "journal_path",
    "vault_auth_principal_id", "vault_admin_domain_id", "vault_account_or_tenant_id",
    "rpc_credential_principal_id", "rpc_provider_domain_id", "rpc_account_or_project_id",
))
def test_p0c3a_collision_checks_are_composed_not_bypassed(attribute):
    a, b, ma, mb = _pair()
    changed_config = replace(b, **{attribute: getattr(a, attribute)})
    changed_manifest = IndependentSignerDeploymentManifest.from_mapping(_manifest_mapping(changed_config))
    with pytest.raises(IndependentSignerDeploymentAcceptanceError):
        validate_operated_signer_deployment(a, changed_config, ma, changed_manifest)


@pytest.mark.parametrize("attribute, value", (
    ("deployment_host_id", "host-next"),
    ("runtime_principal_id", "principal-next"),
    ("tls_termination_domain_id", "tls-next"),
    ("server_worker_count", 2),
    ("execution_concurrency_limit", 2),
    ("service_config_fingerprint", "0" * 64),
))
def test_each_required_deployment_fingerprint_field_is_bound(attribute, value):
    _, _, manifest, _ = _pair()
    assert replace(manifest, **{attribute: value}).fingerprint() != manifest.fingerprint()


def test_acceptance_reuses_p0c3a_topology_validator(monkeypatch):
    import src.independent_signer_deployment as deployment
    a, b, ma, mb = _pair()
    calls, original = [], deployment.validate_independent_signer_topology
    monkeypatch.setattr(deployment, "validate_independent_signer_topology", lambda *args: calls.append(args) or original(*args))
    assert validate_operated_signer_deployment(a, b, ma, mb).classification == "OPERATED_2OF2_ACCEPTABLE"
    assert calls == [(a, b)]


def test_acceptance_is_pure_and_constructs_no_runtime_components_or_secret_reads(monkeypatch):
    from src.independent_signer_execution import IndependentSignerEngine, IndependentSignerVaultAdapter
    from src.independent_signer_journal import IndependentSignerJournal
    from src.independent_signer_service import create_independent_signer_service
    from src.vault_transit import VaultTransitClient
    a, b, ma, mb = _pair()
    calls = []
    def blocked(*args, **kwargs):
        calls.append((args, kwargs)); raise AssertionError("runtime construction forbidden")
    monkeypatch.setattr(IndependentSignerEngine, "__init__", blocked)
    monkeypatch.setattr(IndependentSignerVaultAdapter, "__init__", blocked)
    monkeypatch.setattr(IndependentSignerJournal, "__init__", blocked)
    monkeypatch.setattr(VaultTransitClient, "__init__", blocked)
    monkeypatch.setattr("src.independent_signer_service.create_independent_signer_service", blocked)
    monkeypatch.setattr(os, "getenv", blocked)
    assert validate_operated_signer_deployment(a, b, ma, mb).classification == "OPERATED_2OF2_ACCEPTABLE"
    assert calls == []
