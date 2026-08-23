from dataclasses import replace

import pytest
from solders.hash import Hash
from solders.pubkey import Pubkey

from src.runtime_config import (
    CoordinatorRuntimeConfig,
    CoordinatorVerifierServiceConfig,
    InternalAuth,
    ResolverRuntimeConfig,
    SettlementExecutionRuntimeConfig,
    SettlementFeePayerConfig,
    SettlementRpcConfig,
    SolanaRuntimeConfig,
    VaultSignerConfig,
    VaultSignerKeyEpoch,
    VaultSigningConfig,
    VerifierRuntimeIdentity,
    Limits,
    Freshness,
)
from src.secure_settlement_runtime import (
    SecureSettlementPolicy,
    SecureSettlementRuntimeError,
    validate_secure_settlement_topology,
)


GENESIS = str(Hash.from_bytes(bytes([7]) * 32))
PROGRAM = str(Pubkey.from_bytes(bytes([1]) * 32))
A_PK = str(Pubkey.from_bytes(bytes([2]) * 32))
B_PK = str(Pubkey.from_bytes(bytes([3]) * 32))


def _client(slot):
    return CoordinatorVerifierServiceConfig(
        base_url=f"http://verifier-{slot.lower()}:830{1 if slot == 'A' else 2}",
        auth_token_env=f"VERIFIER_{slot}_TOKEN",
        expected_verifier_id=f"prophet.verifier.runtime.{slot.lower()}",
        expected_verifier_version="2.0.0",
        expected_verifier_implementation_digest=("46" if slot == "A" else "47") * 32,
        request_timeout_seconds=5,
        attestation_public_key=A_PK if slot == "A" else B_PK,
        attestation_private_key_env=f"VERIFIER_{slot}_ATTESTATION_KEY",
    )


def _signer(slot, pubkey):
    epoch = VaultSignerKeyEpoch(1, pubkey, 0, None)
    return VaultSignerConfig(
        signer_id=f"settlement-{slot.lower()}",
        key_name=f"key-{slot.lower()}",
        expected_public_key=pubkey,
        expected_key_version=1,
        key_epochs=(epoch,),
    )


def _runtime(tmp_path):
    coordinator = CoordinatorRuntimeConfig(
        _client("A"),
        _client("B"),
        str(tmp_path / "coordinator.sqlite"),
        InternalAuth("COORDINATOR_TOKEN"),
        15,
    )
    signing = VaultSigningConfig(
        "https://vault.example",
        "LEGACY_SHARED_TOKEN_DISABLED",
        "transit",
        5,
        "vault-transit",
        _signer("A", A_PK),
        _signer("B", B_PK),
        str(tmp_path / "signing.sqlite"),
    )
    execution = SettlementExecutionRuntimeConfig(
        "RPC_URL",
        "devnet",
        GENESIS,
        SettlementFeePayerConfig("FEE_PAYER_PATH"),
        SettlementRpcConfig(10, "confirmed"),
        str(tmp_path / "submission.sqlite"),
    )
    return ResolverRuntimeConfig(
        1,
        "public-devnet",
        "production",
        SolanaRuntimeConfig("devnet", GENESIS, PROGRAM),
        2,
        VerifierRuntimeIdentity("prophet.coordinator.runtime", "2.0.0"),
        ("pyth",),
        Limits(1048576, 10),
        Freshness(300, 60),
        InternalAuth("UNUSED"),
        None,
        None,
        coordinator,
        signing,
        execution,
    )


def _policy(**changes):
    values = dict(
        resolution_mode="secure-coordinator",
        direct_attester_settlement_enabled=False,
        generic_remote_signer_settlement_enabled=False,
        required_signer_count=2,
        api_auth_token_env="SETTLEMENT_API_TOKEN",
        signer_a_vault_token_env="VAULT_A_TOKEN",
        signer_b_vault_token_env="VAULT_B_TOKEN",
    )
    values.update(changes)
    return SecureSettlementPolicy(**values)


def test_secure_topology_is_accepted_structurally(tmp_path):
    validate_secure_settlement_topology(_runtime(tmp_path), _policy())


@pytest.mark.parametrize("environment", ["public-devnet", "mainnet"])
def test_secure_topology_rejects_collapsed_verifier_attestation_identities(tmp_path, environment):
    runtime = replace(_runtime(tmp_path), environment=environment)
    collapsed = replace(
        runtime,
        coordinator=replace(
            runtime.coordinator,
            verifier_b=replace(
                runtime.coordinator.verifier_b,
                attestation_public_key=runtime.coordinator.verifier_a.attestation_public_key,
            ),
        ),
    )
    with pytest.raises(SecureSettlementRuntimeError, match="verifier_attestation_public_keys_must_be_distinct"):
        validate_secure_settlement_topology(collapsed, _policy())


def test_secure_topology_rejects_collapsed_verifier_attestation_key_reference(tmp_path):
    runtime = _runtime(tmp_path)
    collapsed = replace(
        runtime,
        coordinator=replace(
            runtime.coordinator,
            verifier_b=replace(
                runtime.coordinator.verifier_b,
                attestation_private_key_env=runtime.coordinator.verifier_a.attestation_private_key_env,
            ),
        ),
    )
    with pytest.raises(SecureSettlementRuntimeError, match="verifier_attestation_key_refs_must_be_distinct"):
        validate_secure_settlement_topology(collapsed, _policy())


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda r: replace(r, coordinator=None), "coordinator_configuration_required"),
        (
            lambda r: replace(
                r,
                coordinator=replace(
                    r.coordinator,
                    verifier_b=replace(
                        r.coordinator.verifier_b,
                        base_url=r.coordinator.verifier_a.base_url,
                    ),
                ),
            ),
            "verifier_service_urls_must_be_distinct",
        ),
        (
            lambda r: replace(
                r,
                coordinator=replace(r.coordinator, sqlite_path=":memory:"),
            ),
            "coordinator_sqlite_path",
        ),
        (
            lambda r: replace(
                r,
                signing=replace(r.signing, journal_path="relative.sqlite"),
            ),
            "signing_journal_path",
        ),
        (
            lambda r: replace(
                r,
                settlement_execution=replace(
                    r.settlement_execution, journal_path=":memory:"
                ),
            ),
            "submission_journal_path",
        ),
    ],
)
def test_secure_topology_rejects_missing_or_nonpersistent_runtime(tmp_path, mutate, match):
    with pytest.raises(SecureSettlementRuntimeError, match=match):
        validate_secure_settlement_topology(mutate(_runtime(tmp_path)), _policy())


@pytest.mark.parametrize(
    "policy,match",
    [
        (_policy(resolution_mode="legacy-test"), "secure_coordinator_mode_required"),
        (_policy(direct_attester_settlement_enabled=True), "direct_attester"),
        (
            _policy(generic_remote_signer_settlement_enabled=True),
            "generic_remote_signer",
        ),
        (_policy(required_signer_count=1), "strict_2of2_required"),
        (
            _policy(signer_b_vault_token_env="VAULT_A_TOKEN"),
            "signer_vault_auth_refs_must_be_distinct",
        ),
    ],
)
def test_secure_topology_rejects_insecure_policy(tmp_path, policy, match):
    with pytest.raises(SecureSettlementRuntimeError, match=match):
        validate_secure_settlement_topology(_runtime(tmp_path), policy)


def test_secure_topology_rejects_same_signer_identity(tmp_path):
    runtime = _runtime(tmp_path)
    shared = replace(runtime.signing.signer_b, signer_id=runtime.signing.signer_a.signer_id)
    runtime = replace(runtime, signing=replace(runtime.signing, signer_b=shared))
    with pytest.raises(SecureSettlementRuntimeError, match="signer_domains_must_be_distinct"):
        validate_secure_settlement_topology(runtime, _policy())
