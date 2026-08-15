import hashlib
from dataclasses import replace

import pytest
from solders.keypair import Keypair
from solders.signature import Signature

from src.resolver_v2_pipeline import build_legacy_settlement_message
from src.runtime_config import parse_runtime_config
from src.vault_transit_signer_identity import (
    DeterministicTestVaultTransit,
    VaultSignerIdentityCollision,
    VaultSignerKeyVersionError,
    VaultSignerSignatureError,
    VaultTransitSignature,
    VaultTransitSignerClient,
)
from src.vault_transit_threshold_signer import (
    ThresholdResolutionSigner,
    ThresholdSignerAFailure,
    ThresholdSignerBFailure,
    ThresholdSignerIdentityMismatch,
    ThresholdSignerMessageMismatch,
    ThresholdSignerSignatureInvalid,
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


def _raw(a, b):
    signer = lambda ident, key, pub: {"signer_id":ident,"key_name":key,"expected_public_key":str(pub),"expected_key_version":1}
    return {"schema_version":1,"environment":"localtest","mode":"test","solana":{"cluster":"localnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"test","version":"2.0.0"},"allowed_adapters":["pyth"],"limits":{"request_max_bytes":1,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"INTERNAL"},"signing":{"vault":{"address":"http://vault.test","auth":{"token_env":"VAULT_TOKEN"},"transit_mount":"transit","request_timeout_seconds":1,"backend":"deterministic-test"},"signers":{"a":signer("signer-a","key-a",a),"b":signer("signer-b","key-b",b)}}}


def _threshold(monkeypatch, *, versions=None):
    first, second = Keypair.from_seed(bytes(range(32))), Keypair.from_seed(bytes(range(32, 64)))
    runtime = parse_runtime_config(_raw(first.pubkey(), second.pubkey()))
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    metadata = lambda key: {"type":"ed25519","latest_version":1,"supports_signing":True,"keys":{"1":{"public_key":str(key.pubkey())}}}
    transport = DeterministicTestVaultTransit({"key-a":metadata(first),"key-b":metadata(second)}, signers_by_key={"key-a":first,"key-b":second}, reported_versions=versions)
    a = VaultTransitSignerClient.from_runtime(runtime, slot="A", transport=transport)
    b = VaultTransitSignerClient.from_runtime(runtime, slot="B", transport=transport)
    return ThresholdResolutionSigner(signer_a=a, signer_b=b), a, b, first, second


def test_two_of_two_frozen_canonical_bytes_and_existing_ed25519_layout(monkeypatch):
    threshold, _, _, first, second = _threshold(monkeypatch)
    message = _message()
    assert message.hex() == GOLDEN_RESOLVE_V2_HEX
    bundle = threshold.sign_2_of_2(message)
    assert bundle.signer_a_id == "signer-a" and bundle.signer_b_id == "signer-b"
    assert Signature.from_bytes(bundle.signer_a_signature).verify(first.pubkey(), message)
    assert Signature.from_bytes(bundle.signer_b_signature).verify(second.pubkey(), message)
    # Existing Prophet consumes one standard Ed25519 instruction per pinned signer.
    from prophet_sdk.ed25519 import build_ed25519_ix
    for signature, public_key in ((bundle.signer_a_signature, first.pubkey()), (bundle.signer_b_signature, second.pubkey())):
        ix = build_ed25519_ix(message, signature, bytes(public_key))
        assert bytes(ix.data)[16:48] == bytes(public_key) and bytes(ix.data)[48:112] == signature and bytes(ix.data)[112:] == message


def test_one_of_two_never_returns_success(monkeypatch):
    threshold, a, b, _, _ = _threshold(monkeypatch)
    class FailingB:
        signer = b.signer
        def validate_identity(self): return b.validate_identity()
        def sign_canonical_message(self, message): raise VaultSignerSignatureError("unavailable")
    with pytest.raises(ThresholdSignerBFailure):
        ThresholdResolutionSigner(signer_a=a, signer_b=FailingB()).sign_2_of_2(_message())
    class FailingA:
        signer = a.signer
        def validate_identity(self): return a.validate_identity()
        def sign_canonical_message(self, message): raise VaultSignerSignatureError("unavailable")
    with pytest.raises(ThresholdSignerAFailure):
        ThresholdResolutionSigner(signer_a=FailingA(), signer_b=b).sign_2_of_2(_message())


@pytest.mark.parametrize("slot", ["A", "B"])
def test_invalid_signature_in_either_required_slot_rejects(monkeypatch, slot):
    threshold, a, b, _, _ = _threshold(monkeypatch)
    class Invalid:
        signer = a.signer if slot == "A" else b.signer
        def validate_identity(self): return (a if slot == "A" else b).validate_identity()
        def sign_canonical_message(self, message):
            client = a if slot == "A" else b
            identity = client.validate_identity()
            return VaultTransitSignature(identity.signer_id, identity.vault_key_version, identity.public_key, bytes(64), hashlib.sha256(message).hexdigest())
    if slot == "A":
        broken = ThresholdResolutionSigner(signer_a=Invalid(), signer_b=b)
    else:
        broken = ThresholdResolutionSigner(signer_a=a, signer_b=Invalid())
    with pytest.raises(ThresholdSignerSignatureInvalid):
        broken.sign_2_of_2(_message())


def test_substitution_duplicate_and_wrong_versions_reject(monkeypatch):
    threshold, a, b, _, _ = _threshold(monkeypatch)
    message = _message()
    valid = threshold.sign_2_of_2(message)
    with pytest.raises(ThresholdSignerIdentityMismatch):
        threshold.validate_bundle(replace(valid, signer_a_id=valid.signer_b_id, signer_a_public_key=valid.signer_b_public_key, signer_a_signature=valid.signer_b_signature), message)
    with pytest.raises(ThresholdSignerIdentityMismatch):
        threshold.validate_bundle(replace(valid, signer_b_id=valid.signer_a_id, signer_b_public_key=valid.signer_a_public_key, signer_b_signature=valid.signer_a_signature), message)
    with pytest.raises(VaultSignerKeyVersionError):
        threshold.validate_bundle(replace(valid, signer_b_key_version=2), message)
    wrong, _, _, _, _ = _threshold(monkeypatch, versions={"key-b":2})
    with pytest.raises(ThresholdSignerBFailure):
        wrong.sign_2_of_2(message)
    wrong_a, _, _, _, _ = _threshold(monkeypatch, versions={"key-a":2})
    with pytest.raises(ThresholdSignerAFailure):
        wrong_a.sign_2_of_2(message)


def test_collapsed_signer_roles_reject_at_construction(monkeypatch):
    _, a, b, _, _ = _threshold(monkeypatch)
    with pytest.raises(VaultSignerIdentityCollision):
        ThresholdResolutionSigner(signer_a=a, signer_b=a)
    # A distinct client object with A's pinned public identity still cannot
    # occupy role B.
    clone = VaultTransitSignerClient(
        signing=b.signing,
        signer=replace(b.signer, expected_public_key=a.signer.expected_public_key),
        config_fingerprint="test", vault_token="token", transport=b._transport,
    )
    with pytest.raises(VaultSignerIdentityCollision):
        ThresholdResolutionSigner(signer_a=clone, signer_b=b)


def test_cross_message_mixing_and_mutated_message_reject(monkeypatch):
    threshold, a, b, _, _ = _threshold(monkeypatch)
    first, second = _message(), _message(outcome="YES")
    sig_a, sig_b = a.sign_canonical_message(first), b.sign_canonical_message(second)
    mixed = threshold.sign_2_of_2(first)
    mixed = replace(mixed, signer_a_signature=sig_a.signature, signer_b_signature=sig_b.signature)
    with pytest.raises(ThresholdSignerSignatureInvalid):
        threshold.validate_bundle(mixed, first)
    valid = threshold.sign_2_of_2(first)
    with pytest.raises(ThresholdSignerMessageMismatch):
        threshold.validate_bundle(valid, second)


def test_runtime_metadata_is_not_signed_and_bundle_is_immutable(monkeypatch):
    threshold, _, _, _, _ = _threshold(monkeypatch)
    message = _message()
    bundle = threshold.sign_2_of_2(message)
    assert bundle.canonical_message_digest == hashlib.sha256(message).hexdigest()
    with pytest.raises(Exception):
        bundle.signer_a_id = "changed"
