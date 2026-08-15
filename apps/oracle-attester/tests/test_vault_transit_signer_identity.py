import pytest
from solders.keypair import Keypair

from src.runtime_config import RuntimeConfigError, parse_runtime_config
from src.vault_transit import VaultTransitError
from src.vault_transit_signer_identity import (
    DeterministicTestVaultTransit,
    VaultSignerAuthenticationError,
    VaultSignerKeyMissingError,
    VaultSignerKeyTypeError,
    VaultSignerKeyVersionError,
    VaultSignerMetadataError,
    VaultSignerPermissionError,
    VaultSignerPublicKeyMismatch,
    VaultSignerTransportError,
    VaultTransitSignerClient,
    validate_signer_pair,
)


def _raw(first, second, *, backend="deterministic-test", environment="localtest", mode="test"):
    signer = lambda signer_id, key_name, public: {"signer_id": signer_id, "key_name": key_name, "expected_public_key": str(public), "expected_key_version": 1}
    return {"schema_version":1,"environment":environment,"mode":mode,"solana":{"cluster":"localnet" if environment == "localtest" else "devnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"test","version":"2.0.0"},"allowed_adapters":["pyth"],"limits":{"request_max_bytes":1,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"INTERNAL"},"signing":{"vault":{"address":"http://vault.test" if environment == "localtest" else "https://vault.example","auth":{"token_env":"VAULT_TOKEN"},"transit_mount":"transit","request_timeout_seconds":1,"backend":backend},"signers":{"a":signer("signer-a", "key-a", first),"b":signer("signer-b", "key-b", second)}}}


def _metadata(public, *, key_type="ed25519", version=1):
    return {"type": key_type, "latest_version": version, "supports_signing": True, "keys": {str(version): {"public_key": str(public)}}}


def _clients(monkeypatch):
    first, second = Keypair(), Keypair()
    config = parse_runtime_config(_raw(first.pubkey(), second.pubkey()))
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    transport = DeterministicTestVaultTransit({"key-a": _metadata(first.pubkey()), "key-b": _metadata(second.pubkey())})
    return config, VaultTransitSignerClient.from_runtime(config, slot="A", transport=transport), VaultTransitSignerClient.from_runtime(config, slot="B", transport=transport), first, second


def test_valid_distinct_a_b_metadata_is_pinned_and_identity_is_immutable(monkeypatch):
    config, signer_a, signer_b, first, second = _clients(monkeypatch)
    identity_a, identity_b = validate_signer_pair(signer_a, signer_b)
    assert identity_a.public_key == str(first.pubkey()) and identity_b.public_key == str(second.pubkey())
    assert identity_a.key_type == identity_b.key_type == "ed25519"
    assert identity_a.config_fingerprint == config.fingerprint()
    with pytest.raises(Exception):
        identity_a.public_key = str(second.pubkey())


@pytest.mark.parametrize("field", ("signer_id", "key_name", "expected_public_key"))
def test_configuration_rejects_signer_identity_collisions(field):
    first, second = Keypair(), Keypair()
    raw = _raw(first.pubkey(), second.pubkey())
    raw["signing"]["signers"]["b"][field] = raw["signing"]["signers"]["a"][field]
    with pytest.raises(RuntimeConfigError):
        parse_runtime_config(raw)


def test_missing_or_empty_vault_secret_fails_closed(monkeypatch):
    first, second = Keypair(), Keypair()
    config = parse_runtime_config(_raw(first.pubkey(), second.pubkey()))
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises(VaultSignerAuthenticationError):
        VaultTransitSignerClient.from_runtime(config, slot="A", transport=DeterministicTestVaultTransit({}))
    monkeypatch.setenv("VAULT_TOKEN", "")
    with pytest.raises(VaultSignerAuthenticationError):
        VaultTransitSignerClient.from_runtime(config, slot="A", transport=DeterministicTestVaultTransit({}))


@pytest.mark.parametrize("error,expected", [
    (VaultTransitError("down"), VaultSignerTransportError),
    (VaultTransitError("denied", status_code=401), VaultSignerAuthenticationError),
    (VaultTransitError("forbidden", status_code=403), VaultSignerPermissionError),
    (VaultTransitError("missing", status_code=404), VaultSignerKeyMissingError),
])
def test_vault_transport_errors_are_typed(monkeypatch, error, expected):
    config, signer_a, _, _, _ = _clients(monkeypatch)
    class Broken:
        def read_key_metadata(self, _): raise error
    client = VaultTransitSignerClient.from_runtime(config, slot="A", transport=Broken())
    with pytest.raises(expected):
        client.validate_identity()


@pytest.mark.parametrize("metadata,expected", [
    ({"type":"rsa","keys":{"1":{"public_key":"11111111111111111111111111111111"}}}, VaultSignerKeyTypeError),
    ({"type":"ed25519","keys":{}}, VaultSignerKeyVersionError),
    ({"type":"ed25519","keys":{"1":{"public_key":"bad"}}}, VaultSignerMetadataError),
])
def test_key_type_version_and_public_key_encoding_fail_closed(monkeypatch, metadata, expected):
    config, _, _, _, _ = _clients(monkeypatch)
    client = VaultTransitSignerClient.from_runtime(config, slot="A", transport=DeterministicTestVaultTransit({"key-a": metadata}))
    with pytest.raises(expected):
        client.validate_identity()


def test_public_key_pin_mismatch_and_test_backend_production_separation(monkeypatch):
    config, _, _, first, second = _clients(monkeypatch)
    mismatch = VaultTransitSignerClient.from_runtime(config, slot="A", transport=DeterministicTestVaultTransit({"key-a": _metadata(second.pubkey())}))
    with pytest.raises(VaultSignerPublicKeyMismatch):
        mismatch.validate_identity()
    with pytest.raises(RuntimeConfigError):
        parse_runtime_config(_raw(first.pubkey(), second.pubkey(), environment="public-devnet", mode="production"))


def test_signing_fingerprint_is_deterministic_and_binds_key_identity():
    first, second = Keypair(), Keypair()
    raw = _raw(first.pubkey(), second.pubkey())
    original = parse_runtime_config(raw)
    assert original.fingerprint() == parse_runtime_config(dict(reversed(list(raw.items())))).fingerprint()
    changed = _raw(first.pubkey(), second.pubkey())
    changed["signing"]["signers"]["a"]["key_name"] = "key-a-next"
    assert original.fingerprint() != parse_runtime_config(changed).fingerprint()
