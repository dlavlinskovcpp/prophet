"""Permanent compatibility proofs for the existing signed-oracle wire format."""

import hashlib
from pathlib import Path
import tempfile

import pytest
from solders.keypair import Keypair

from src.resolver_v2_adapters import (
    OracleKeyEpoch,
    OracleKeyring,
    SignedOracleAdapter,
    SIGNED_ORACLE_VERSION,
    SignedOracleMaterial,
    signed_oracle_message,
)
from src.resolver_v2_pipeline import AcquiredEvidence, normalize_evidence
from src.runtime_config import parse_runtime_config
from src.signed_oracle_runtime_keys import load_trusted_oracle_key_registry
from prophet_sdk import resolver_v2


H = lambda byte: f"{byte:02x}" * 32
_SEED = bytes(range(32))
_PUBLIC_KEY = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF"
_FROZEN_PAYLOAD = {
    "schema": "prophet.signed-oracle-observation.v2",
    "schema_version": "2.0.0",
    "resolver_id": "signed_oracle-resolver",
    "market": H(40),
    "outcome": "yes",
    "source_timestamp_ms": "90",
    "sequence": "7",
    "cluster_genesis_hash": H(41),
    "replay_domain": H(42),
}
_FROZEN_MESSAGE_HEX = "50524f504845545f5349474e45445f4f5241434c455f563200240070726f706865742e7369676e65642d6f7261636c652d6f62736572766174696f6e2e76320500322e302e30a40100007b22636c75737465725f67656e657369735f68617368223a2232393239323932393239323932393239323932393239323932393239323932393239323932393239323932393239323932393239323932393239323932393239222c226d61726b6574223a2232383238323832383238323832383238323832383238323832383238323832383238323832383238323832383238323832383238323832383238323832383238222c226f7574636f6d65223a22796573222c227265706c61795f646f6d61696e223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c227265736f6c7665725f6964223a227369676e65645f6f7261636c652d7265736f6c766572222c22736368656d61223a2270726f706865742e7369676e65642d6f7261636c652d6f62736572766174696f6e2e7632222c22736368656d615f76657273696f6e223a22322e302e30222c2273657175656e6365223a2237222c22736f757263655f74696d657374616d705f6d73223a223930227d"
_FROZEN_MESSAGE_HASH = "60efde57d0dd2065a76c743e6bac5044396477d549eb0557dbad7bd60fd2ad23"
_FROZEN_SIGNATURE_HEX = "21659829b226ddfa45582382cf06f25321cd78aa1d31641f7222cd12306099b71bdae8f1721503d50fffd1415374ac27e37b90ff6280510b313db5ac3bdf5b02"


def _adapter_descriptor():
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": "prophet.verifier.signed-oracle", "adapter_version": "2.0.0", "implementation_digest": H(5)}


def _trust_model():
    return {"schema": "prophet.trust-model-descriptor.v2", "schema_version": "2.0.0", "trust_model_id": "trusted-model", "trust_model_version": "2.0.0", "document_hash": H(2)}


def _definition():
    return {
        "schema": "prophet.resolver-definition.v2", "schema_version": "2.0.0", "resolver_id": _FROZEN_PAYLOAD["resolver_id"], "resolver_type": "signed_oracle",
        "adapter": {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": "prophet.resolver.signed-oracle", "adapter_version": "2.0.0", "implementation_digest": H(4)}, "trust_model": _trust_model(),
        "source": {"message_domain": "PROPHET_SIGNED_ORACLE_V2", "payload_schema": "prophet.signed-oracle-observation.v2", "payload_schema_version": "2.0.0", "market": H(40), "cluster_genesis_hash": H(41), "replay_domain": H(42), "key_set_version": "1.0.0", "max_message_age_ms": "50", "outcome_mapping": {"yes": "YES", "no": "NO"}, "require_monotonic_sequence": True},
        "verification_policy": {"fail_closed": True}, "evaluation": {"mode": "bound"}, "timing": {"not_before_ms": "0", "observation_deadline_ms": "999999", "max_evidence_age_ms": "100"}, "conflict_policy": {"mode": "reject"}, "fallback_policy": {"outcome": "INVALID"},
    }


def _runtime_raw(path, identity):
    return {"schema_version": 1, "environment": "public-devnet", "mode": "production", "solana": {"cluster": "devnet", "genesis_hash": "g", "prophet_program_id": "p"}, "resolver_v2": {"schema_version": 2}, "verifier": {"implementation_id": "a", "version": "2"}, "allowed_adapters": ["signed-oracle"], "limits": {"request_max_bytes": 1, "request_timeout_seconds": 1}, "freshness": {"default_max_evidence_age_seconds": 1, "default_max_verification_age_seconds": 1}, "internal_auth": {"token_env": "TOKEN"}, "signed_oracle": {"registry_path": str(path), "key_bindings": [{"key_id": "old", "key_set_version": "1.0.0", "oracle_identity": identity}]}}


def _registry_text(*identities):
    records = "\n".join(f'- oracle_identity: {identity}\n  resolver_ids: [{_FROZEN_PAYLOAD["resolver_id"]}]\n  public_key: "{_PUBLIC_KEY}"\n  key_epoch: epoch-{identity}\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active' for identity in identities)
    return f"overlap_ms: 0\nrecords:\n{records}\n"


def _signed_evidence(message, signature, *, key_id="old", key_set_version="1.0.0"):
    definition = _definition()
    raw = resolver_v2.canonical_json_bytes({"key_id": key_id, "key_set_version": key_set_version, "message_hex": message.hex(), "signature_hex": signature.hex()})
    acquired = AcquiredEvidence(H(4), definition["resolver_id"], key_id, "100", raw, {"key_set_version": key_set_version, "message_hash": hashlib.sha256(message).hexdigest(), "replay_domain": H(42)}, source_time_ms=str(_FROZEN_PAYLOAD["source_timestamp_ms"]), source_sequence=str(_FROZEN_PAYLOAD["sequence"]), acquisition_id="frozen")
    return normalize_evidence(acquired, definition_hash=resolver_v2.resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "signed"}, provenance={"signature_scheme": "ed25519"})


def _legacy_adapter():
    return SignedOracleAdapter(adapter_digest=H(4), verifier_descriptor=_adapter_descriptor(), keyring=OracleKeyring([OracleKeyEpoch("old", _PUBLIC_KEY, "1.0.0", "0", "1000")]), clock_ms=lambda: 100)


def test_signed_oracle_canonical_message_golden_vector_and_hash():
    message = signed_oracle_message(_FROZEN_PAYLOAD)
    assert message.hex() == _FROZEN_MESSAGE_HEX
    assert hashlib.sha256(message).hexdigest() == _FROZEN_MESSAGE_HASH


def test_signed_oracle_runtime_metadata_is_out_of_band_from_message_bytes():
    with tempfile.TemporaryDirectory(prefix="prophet-canonical-", dir="/private/tmp") as root:
        registry_a_path, registry_b_path = Path(root) / "registry-a.yaml", Path(root) / "registry-b.yaml"
        registry_a_path.write_text(_registry_text("oracle-a")); registry_b_path.write_text(_registry_text("oracle-b", "oracle-a"))
        config_a, config_b = parse_runtime_config(_runtime_raw(registry_a_path, "oracle-a")), parse_runtime_config(_runtime_raw(registry_b_path, "oracle-b"))
        registry_a, registry_b = load_trusted_oracle_key_registry(registry_a_path), load_trusted_oracle_key_registry(registry_b_path)
        assert config_a.fingerprint() != config_b.fingerprint() and registry_a.fingerprint() != registry_b.fingerprint()
        adapter_a = SignedOracleAdapter.from_runtime(runtime_config=config_a, registry=registry_a, resolver_definition=_definition(), verifier_descriptor=_adapter_descriptor(), message_version=SIGNED_ORACLE_VERSION, clock_ms=lambda: 100)
        adapter_b = SignedOracleAdapter.from_runtime(runtime_config=config_b, registry=registry_b, resolver_definition=_definition(), verifier_descriptor=_adapter_descriptor(), message_version=SIGNED_ORACLE_VERSION, clock_ms=lambda: 100)
        assert adapter_a.keyring.bindings[("old", "1.0.0")].oracle_identity == "oracle-a"
        assert adapter_b.keyring.bindings[("old", "1.0.0")].oracle_identity == "oracle-b"
        assert signed_oracle_message(_FROZEN_PAYLOAD) == signed_oracle_message(_FROZEN_PAYLOAD) == bytes.fromhex(_FROZEN_MESSAGE_HEX)


def test_signed_oracle_frozen_signature_verifies_through_runtime_and_legacy_paths():
    keypair = Keypair.from_seed(_SEED); message = signed_oracle_message(_FROZEN_PAYLOAD); signature = bytes(keypair.sign_message(message))
    assert str(keypair.pubkey()) == _PUBLIC_KEY and message.hex() == _FROZEN_MESSAGE_HEX and signature.hex() == _FROZEN_SIGNATURE_HEX
    with tempfile.TemporaryDirectory(prefix="prophet-canonical-", dir="/private/tmp") as root:
        registry_path = Path(root) / "registry.yaml"; registry_path.write_text(_registry_text("oracle"))
        runtime = SignedOracleAdapter.from_runtime(runtime_config=parse_runtime_config(_runtime_raw(registry_path, "oracle")), registry=load_trusted_oracle_key_registry(registry_path), resolver_definition=_definition(), verifier_descriptor=_adapter_descriptor(), message_version=SIGNED_ORACLE_VERSION, clock_ms=lambda: 100)
        evidence = _signed_evidence(message, signature)
        assert runtime.verify(_definition(), evidence, _trust_model()).status == "VERIFIED"
        assert _legacy_adapter().verify(_definition(), evidence, _trust_model()).status == "VERIFIED"


@pytest.mark.parametrize("field,value", [("resolver_id", "other-resolver"), ("market", H(99)), ("outcome", "no"), ("source_timestamp_ms", "91"), ("sequence", "8"), ("cluster_genesis_hash", H(99)), ("replay_domain", H(99)), ("key_id", "other"), ("key_set_version", "1.0.1")])
def test_signed_oracle_frozen_signature_rejects_single_field_mutation(field, value):
    payload, key_id, key_set_version = dict(_FROZEN_PAYLOAD), "old", "1.0.0"
    if field in payload:
        payload[field] = value
    elif field == "key_id":
        key_id = value
    else:
        key_set_version = value
    original_signature = bytes(Keypair.from_seed(_SEED).sign_message(bytes.fromhex(_FROZEN_MESSAGE_HEX)))
    report = _legacy_adapter().verify(_definition(), _signed_evidence(signed_oracle_message(payload), original_signature, key_id=key_id, key_set_version=key_set_version), _trust_model())
    assert report.status == "REJECTED"
