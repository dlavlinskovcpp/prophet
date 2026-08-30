import os

import pytest
from solders.signature import Signature
from solders.pubkey import Pubkey

from src.independent_signer_execution import IndependentSignerStartupError, IndependentSignerVaultAdapter
from src.independent_signer_execution import IndependentSignerEngine
from src.independent_signer_journal import IndependentSignerBinding, IndependentSignerJournal
from src.independent_signer_runtime import IndependentSignerServiceConfig
from src.localtest_file_vault_transport import LocaltestFileVaultTransport, LocaltestFileVaultTransportError
from src.signer_authorization import Account, SignerAuthorizationConfig, VerifierPin
from src.verifier_attestation import VerifierAttestationSigner, settlement_authorization_job_id
from tests.test_signer_authorization import GEN, PROGRAM, Rpc, market, notary, H


def _path(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    state = tmp_path / "signer-a"
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    return state / "signer.seed"


def _transport(tmp_path, *, role="A", initialize=True):
    return LocaltestFileVaultTransport(
        environment="localtest", mode="test", signer_role=role, signer_id=f"signer-{role.lower()}",
        vault_key_name=f"localtest-notary-{role.lower()}", key_version=1,
        seed_path=_path(tmp_path) if role == "A" else _path(tmp_path / "b"), initialize=initialize,
    )


def _message():
    return b"PROPHET_RESOLVE_V2" + bytes(235 - len(b"PROPHET_RESOLVE_V2"))


def _service(public_key):
    return IndependentSignerServiceConfig.from_mapping({
        "environment": "localtest", "mode": "test", "topology_classification": "FUNCTIONAL_TEST_ONLY",
        "signer": {"role": "A", "signer_id": "signer-a", "public_key": public_key, "key_version": 1},
        "vault": {"address": "http://vault.localtest", "transit_mount": "transit", "key_name": "localtest-notary-a", "token_env": "SIGNER_A_VAULT_TOKEN", "admin_domain_id": "vault-a", "account_or_tenant_id": "account-a", "auth_principal_id": "principal-a", "timeout_seconds": 1},
        "rpc": {"url_env": "SIGNER_A_RPC_URL", "provider_domain_id": "rpc-a", "account_or_project_id": "rpc-account-a", "credential_principal_id": "rpc-principal-a"},
        "solana": {"expected_genesis_hash": "00" * 32, "expected_program_id": "11111111111111111111111111111111"},
        "journal_path": "/tmp/localtest-a.sqlite", "admission_token_env": "SIGNER_A_ADMISSION_TOKEN",
    })


def test_create_load_metadata_and_sign(tmp_path):
    first = _transport(tmp_path)
    second = _transport(tmp_path, initialize=False)
    assert first.public_key == second.public_key
    metadata = first.read_key_metadata("localtest-notary-a")
    assert metadata["keys"]["1"]["public_key"] == first.public_key
    version, signature = first.sign_versioned("localtest-notary-a", _message(), key_version=1)
    assert version == 1 and len(signature) == 64
    assert Signature.from_bytes(signature).verify(Pubkey.from_string(first.public_key), _message())


@pytest.mark.parametrize("size", (31, 33))
def test_malformed_seed_is_not_regenerated(tmp_path, size):
    path = _path(tmp_path)
    path.write_bytes(bytes(size)); path.chmod(0o600)
    with pytest.raises(LocaltestFileVaultTransportError, match="seed_size_invalid"):
        _transport(tmp_path, initialize=False)
    assert path.read_bytes() == bytes(size)


def test_symlink_and_permissive_seed_rejected(tmp_path):
    path = _path(tmp_path)
    target = tmp_path / "target"; target.write_bytes(bytes(32)); target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(LocaltestFileVaultTransportError):
        _transport(tmp_path, initialize=False)
    path.unlink(); path.write_bytes(bytes(32)); path.chmod(0o644)
    with pytest.raises(LocaltestFileVaultTransportError, match="permissions"):
        _transport(tmp_path, initialize=False)


def test_key_and_message_binding(tmp_path):
    transport = _transport(tmp_path)
    with pytest.raises(LocaltestFileVaultTransportError): transport.read_key_metadata("other")
    with pytest.raises(LocaltestFileVaultTransportError): transport.sign_versioned("other", _message(), key_version=1)
    with pytest.raises(LocaltestFileVaultTransportError): transport.sign_versioned("localtest-notary-a", _message(), key_version=2)
    with pytest.raises(LocaltestFileVaultTransportError): transport.sign_versioned("localtest-notary-a", b"x" * 235, key_version=1)
    with pytest.raises(LocaltestFileVaultTransportError): transport.sign_versioned("localtest-notary-a", b"x", key_version=1)
    assert not hasattr(transport, "sign") and not hasattr(transport, "sign_digest")


@pytest.mark.parametrize("environment,mode", (("public-devnet", "production"), ("devnet", "test"), ("localtest", "production")))
def test_non_localtest_rejected_before_file_access(tmp_path, environment, mode):
    path = tmp_path / "missing" / "signer.seed"
    with pytest.raises(LocaltestFileVaultTransportError, match="environment_rejected"):
        LocaltestFileVaultTransport(environment=environment, mode=mode, signer_role="A", signer_id="signer-a", vault_key_name="a", key_version=1, seed_path=path)
    assert not path.parent.exists()


def test_explicit_transport_does_not_require_unused_vault_token(tmp_path, monkeypatch):
    monkeypatch.delenv("SIGNER_A_VAULT_TOKEN", raising=False)
    transport = _transport(tmp_path)
    adapter = IndependentSignerVaultAdapter(_service(transport.public_key), transport=transport)
    assert adapter.validate_identity().public_key == transport.public_key


def test_production_vault_path_still_requires_token(tmp_path, monkeypatch):
    monkeypatch.delenv("SIGNER_A_VAULT_TOKEN", raising=False)
    transport = _transport(tmp_path)
    with pytest.raises(IndependentSignerStartupError, match="vault_token_missing"):
        IndependentSignerVaultAdapter(_service(transport.public_key))


def test_real_p0c1_p0c2_engine_uses_localtest_transport(tmp_path):
    transport = _transport(tmp_path)
    own = transport.public_key
    counterpart = str(__import__("solders.keypair", fromlist=["Keypair"]).Keypair.from_seed(bytes(range(32, 64))).pubkey())
    verifier_a = __import__("solders.keypair", fromlist=["Keypair"]).Keypair.from_seed(bytes(range(64, 96)))
    verifier_b = __import__("solders.keypair", fromlist=["Keypair"]).Keypair.from_seed(bytes(range(96, 128)))
    notary_address, notary_data = notary(own, counterpart)
    market_address, market_data = market(notary_address)
    binding = {"cluster_genesis_hash": GEN, "program_id": PROGRAM, "market": market_address, "resolver_definition_hash": H(1), "evidence_hash": H(2), "proof_hash": H(3), "public_inputs_hash": H(4)}
    job_id = settlement_authorization_job_id(binding)
    def attestation(key, identifier, digest):
        payload = {"attestation_schema": "prophet.verifier-attestation.v1", "attestation_version": "1", "verifier_id": identifier, "verifier_version": "1.0.0", "verifier_implementation_digest": digest, "job_id": job_id, **binding, "outcome": "YES", "acquired_at_ms": "10", "valid_until_ms": "30"}
        return VerifierAttestationSigner(identifier, "1.0.0", digest, key).sign(payload, now_ms=20).as_transport()
    request = {"schema": "PROPHET_SETTLEMENT_AUTHORIZATION_V1", "version": "1", **{key: binding[key] for key in ("cluster_genesis_hash", "program_id", "market")}, "verifier_a_attestation": attestation(verifier_a, "a", H(5)), "verifier_b_attestation": attestation(verifier_b, "b", H(6))}
    service = _service(own)
    # Preserve the fixture's frozen chain identity while retaining localtest-only
    # service classification and transport construction.
    service = IndependentSignerServiceConfig.from_mapping({**{
        "environment": "localtest", "mode": "test", "topology_classification": "FUNCTIONAL_TEST_ONLY",
        "signer": {"role": "A", "signer_id": "signer-a", "public_key": own, "key_version": 1},
        "vault": {"address": "http://vault.localtest", "transit_mount": "transit", "key_name": "localtest-notary-a", "token_env": "SIGNER_A_VAULT_TOKEN", "admin_domain_id": "vault-a", "account_or_tenant_id": "account-a", "auth_principal_id": "principal-a", "timeout_seconds": 1},
        "rpc": {"url_env": "SIGNER_A_RPC_URL", "provider_domain_id": "rpc-a", "account_or_project_id": "rpc-account-a", "credential_principal_id": "rpc-principal-a"},
        "solana": {"expected_genesis_hash": GEN, "expected_program_id": PROGRAM}, "journal_path": str(tmp_path / "engine.sqlite"), "admission_token_env": "SIGNER_A_ADMISSION_TOKEN"},})
    auth = SignerAuthorizationConfig("A", own, counterpart, VerifierPin(str(verifier_a.pubkey()), "a", "1.0.0", H(5)), VerifierPin(str(verifier_b.pubkey()), "b", "1.0.0", H(6)), GEN, PROGRAM)
    journal = IndependentSignerJournal(tmp_path / "engine.sqlite", binding=IndependentSignerBinding("A", "signer-a", own, 1))
    engine = IndependentSignerEngine(service_config=service, authorization_config=auth, journal=journal, rpc=Rpc({market_address: Account(PROGRAM, market_data), notary_address: Account(PROGRAM, notary_data)}), vault=IndependentSignerVaultAdapter(service, transport=transport))
    try:
        result = engine.execute(request, now_ms=20)
        assert result.state == "SIGNED" and len(result.signature) == 64
        assert engine.execute(request, now_ms=20).signature == result.signature
    finally:
        journal.close()
