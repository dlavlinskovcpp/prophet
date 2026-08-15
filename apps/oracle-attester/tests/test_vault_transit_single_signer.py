import base64
import hashlib

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature

from src.resolver_v2_pipeline import build_legacy_settlement_message
from src.runtime_config import parse_runtime_config
from src.vault_transit import VaultTransitError
from src.vault_transit_signer_identity import (
    DeterministicTestVaultTransit,
    VaultSignerKeyVersionError,
    VaultSignerSignatureError,
    VaultSignerSignatureVerificationError,
    VaultTransitSignerClient,
)


GOLDEN_RESOLVE_V2_HEX = (
    "50524f504845545f5245534f4c56455f5632"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0404040404040404040404040404040404040404040404040404040404040404"
    "f9ffffffffffffff2a00000000000000090000000000000003"
    "0505050505050505050505050505050505050505050505050505050505050505"
    "0606060606060606060606060606060606060606060606060606060606060606"
)


def _message(**changes):
    fields = {"program_id":"11111111111111111111111111111111", "market":"11111111111111111111111111111111", "notary_config":"11111111111111111111111111111111", "resolver_hash":"04" * 32, "open_ts":-7, "resolve_ts":42, "notary_config_version":9, "outcome":"INVALID", "proof_hash":"05" * 32, "public_inputs_hash":"06" * 32}
    fields.update(changes)
    return build_legacy_settlement_message(**fields)


def _raw(first, second):
    signer = lambda signer_id, key_name, public: {"signer_id": signer_id, "key_name": key_name, "expected_public_key": str(public), "expected_key_version": 1}
    return {"schema_version":1,"environment":"localtest","mode":"test","solana":{"cluster":"localnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"test","version":"2.0.0"},"allowed_adapters":["pyth"],"limits":{"request_max_bytes":1,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"INTERNAL"},"signing":{"vault":{"address":"http://vault.test","auth":{"token_env":"VAULT_TOKEN"},"transit_mount":"transit","request_timeout_seconds":1,"backend":"deterministic-test"},"signers":{"a":signer("signer-a", "key-a", first),"b":signer("signer-b", "key-b", second)}}}


def _signers(monkeypatch, *, reported_versions=None):
    first = Keypair.from_seed(bytes(range(32)))
    second = Keypair.from_seed(bytes(range(32, 64)))
    config = parse_runtime_config(_raw(first.pubkey(), second.pubkey()))
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    metadata = lambda key: {"type":"ed25519","latest_version":1,"supports_signing":True,"keys":{"1":{"public_key":str(key.pubkey())}}}
    transport = DeterministicTestVaultTransit({"key-a":metadata(first),"key-b":metadata(second)}, signers_by_key={"key-a":first,"key-b":second}, reported_versions=reported_versions)
    return VaultTransitSignerClient.from_runtime(config, slot="A", transport=transport), VaultTransitSignerClient.from_runtime(config, slot="B", transport=transport), first, second


def test_frozen_resolve_v2_golden_bytes_and_single_vault_signature(monkeypatch):
    message = _message()
    assert message.hex() == GOLDEN_RESOLVE_V2_HEX and len(message) == 235
    signer_a, _, first, _ = _signers(monkeypatch)
    signed = signer_a.sign_canonical_message(message)
    assert signed.message_digest == hashlib.sha256(message).hexdigest()
    assert signed.public_key == str(first.pubkey()) and signed.key_version == 1
    assert Signature.from_bytes(signed.signature).verify(first.pubkey(), message)
    # This is the exact message/signature/public-key layout consumed by the
    # existing Prophet Ed25519 instruction and on-chain verifier.
    from prophet_sdk.ed25519 import build_ed25519_ix
    ix = build_ed25519_ix(message, signed.signature, bytes(first.pubkey()))
    assert bytes(ix.data)[16:48] == bytes(first.pubkey())
    assert bytes(ix.data)[48:112] == signed.signature
    assert bytes(ix.data)[112:] == message


@pytest.mark.parametrize("changes", [
    {"market": str(Pubkey.from_bytes(bytes([1]) * 32))},
    {"resolver_hash": "07" * 32},
    {"outcome": "YES"},
    {"notary_config_version": 10},
    {"resolve_ts": 43},
    {"proof_hash": "08" * 32},
])
def test_one_canonical_settlement_field_mutation_rejects_original_signature(monkeypatch, changes):
    signer_a, _, first, _ = _signers(monkeypatch)
    original = _message()
    signature = signer_a.sign_canonical_message(original).signature
    assert not Signature.from_bytes(signature).verify(first.pubkey(), _message(**changes))


def test_runtime_only_metadata_does_not_change_canonical_settlement_bytes(monkeypatch):
    signer_a, _, _, _ = _signers(monkeypatch)
    original = _message()
    identity = signer_a.validate_identity()
    assert original == _message()
    assert identity.config_fingerprint and signer_a.signer.signer_id == "signer-a"
    assert original.hex() == GOLDEN_RESOLVE_V2_HEX


def test_wrong_signer_and_wrong_vault_key_version_fail_closed(monkeypatch):
    signer_a, signer_b, first, second = _signers(monkeypatch)
    message = _message()
    sig_b = signer_b.sign_canonical_message(message).signature
    assert Signature.from_bytes(sig_b).verify(second.pubkey(), message)
    assert not Signature.from_bytes(sig_b).verify(first.pubkey(), message)
    wrong_version_a, _, _, _ = _signers(monkeypatch, reported_versions={"key-a": 2})
    with pytest.raises(VaultSignerKeyVersionError):
        wrong_version_a.sign_canonical_message(message)


@pytest.mark.parametrize("failure", ["transport", "auth", "permission", "malformed", "unverifiable"])
def test_vault_signing_failures_never_return_a_signature(monkeypatch, failure):
    signer_a, _, _, _ = _signers(monkeypatch)
    class Broken:
        def read_key_metadata(self, key_name): return signer_a._transport.read_key_metadata(key_name)
        def sign_versioned(self, key_name, message, *, key_version):
            if failure == "transport": raise VaultTransitError("down")
            if failure == "auth": raise VaultTransitError("denied", status_code=401)
            if failure == "permission": raise VaultTransitError("forbidden", status_code=403)
            if failure == "malformed": return key_version, b"short"
            return key_version, bytes(64)
    broken = VaultTransitSignerClient(signing=signer_a.signing, signer=signer_a.signer, config_fingerprint="test", vault_token="token", transport=Broken())
    from src.vault_transit_signer_identity import VaultSignerAuthenticationError, VaultSignerPermissionError
    expected = {"auth": VaultSignerAuthenticationError, "permission": VaultSignerPermissionError, "unverifiable": VaultSignerSignatureVerificationError}.get(failure, VaultSignerSignatureError)
    with pytest.raises(expected):
        broken.sign_canonical_message(_message())
