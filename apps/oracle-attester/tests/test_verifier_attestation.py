import json
import base64

import pytest
from solders.keypair import Keypair

from src.verifier_attestation import (
    ATTESTATION_DOMAIN,
    VerifierAttestationError,
    VerifierAttestationSigner,
    attestation_signing_bytes,
    payload_from_verification_result,
    settlement_authorization_job_id,
    settlement_job_id,
    validate_attestation_payload,
    verify_attestation,
)


H = lambda value: f"{value:02x}" * 32
PROGRAM = "11111111111111111111111111111111"
MARKET = "Stake11111111111111111111111111111111111111"


def _result():
    return {
        "schema": "prophet.verification-result.v2", "schema_version": "2.0.0",
        "definition_hash": H(1), "evidence_hash": H(2),
        "verifier": {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": "prophet.verifier.runtime.a", "adapter_version": "2.0.0", "implementation_digest": H(3)},
        "result": "VERIFIED", "checks": [],
        "verified_facts_hex": "7b22636f6e666964656e6365223a2268696768222c226661696c7572655f636f6465223a6e756c6c2c226f7574636f6d65223a22594553222c22737461747573223a225645524946494544222c2276657269666965645f6661637473223a7b7d7d",
        "verified_facts_hash": "35102761430d3fb318a7ce8892e1465d0ef949e14483155b3df52d22c6d63802",
        "observed_at_ms": "100", "valid_from_ms": "100", "valid_until_ms": "200", "finality": None,
    }


def _payload(now_ms=200):
    return payload_from_verification_result(_result(), cluster_genesis_hash=H(4), program_id=PROGRAM, market=MARKET, proof_hash=H(5), public_inputs_hash=H(6), now_ms=now_ms)


def _signer(offset=0):
    return VerifierAttestationSigner("prophet.verifier.runtime.a", "2.0.0", H(3), Keypair.from_seed(bytes(range(offset, offset + 32))))


def test_signed_attestation_round_trip_and_canonical_job_binding():
    signer, payload = _signer(), _payload()
    signed = signer.sign(payload, now_ms=200).as_transport()
    assert attestation_signing_bytes(payload).startswith(ATTESTATION_DOMAIN)
    assert payload["job_id"] == settlement_job_id({key: payload[key] for key in ("cluster_genesis_hash", "program_id", "market", "resolver_definition_hash", "evidence_hash", "proof_hash", "public_inputs_hash")})
    assert verify_attestation(signed, expected_verifier_id="prophet.verifier.runtime.a", expected_verifier_version="2.0.0", expected_verifier_implementation_digest=H(3), expected_public_key=signer.public_key, now_ms=200) == payload


@pytest.mark.parametrize("field,value", [("market", PROGRAM), ("evidence_hash", H(9)), ("proof_hash", H(9)), ("public_inputs_hash", H(9)), ("job_id", H(9))])
def test_attestation_tampering_is_rejected(field, value):
    signed = _signer().sign(_payload(), now_ms=200).as_transport()
    signed["payload"][field] = value
    with pytest.raises(VerifierAttestationError):
        verify_attestation(signed, expected_verifier_id="prophet.verifier.runtime.a", expected_verifier_version="2.0.0", expected_verifier_implementation_digest=H(3), expected_public_key=_signer().public_key)


def test_wrong_key_identity_digest_expiry_and_signature_are_rejected():
    signer, counterpart = _signer(), _signer(32)
    signed = signer.sign(_payload(), now_ms=200).as_transport()
    for kwargs in (
        {"expected_public_key": counterpart.public_key},
        {"expected_verifier_implementation_digest": H(9)},
        {"now_ms": 201},
    ):
        values = {"expected_verifier_id": "prophet.verifier.runtime.a", "expected_verifier_version": "2.0.0", "expected_verifier_implementation_digest": H(3), "expected_public_key": signer.public_key}
        values.update(kwargs)
        with pytest.raises(VerifierAttestationError): verify_attestation(signed, **values)
    signed["signature_hex"] = "00" * 64
    with pytest.raises(VerifierAttestationError): verify_attestation(signed, expected_verifier_id="prophet.verifier.runtime.a", expected_verifier_version="2.0.0", expected_verifier_implementation_digest=H(3), expected_public_key=signer.public_key)


def test_payload_rejects_noncanonical_or_invalid_shapes():
    payload = _payload()
    for changed in (
        {**payload, "unexpected": "x"},
        {key: value for key, value in payload.items() if key != "proof_hash"},
        {**payload, "acquired_at_ms": 100},
        {**payload, "valid_until_ms": "100"},
        {**payload, "outcome": "MAYBE"},
    ):
        with pytest.raises(VerifierAttestationError): validate_attestation_payload(changed)


def test_frozen_vector():
    fixture = json.loads((__import__("pathlib").Path(__file__).parent / "fixtures" / "verifier_attestation_v1.json").read_text())
    signer = _signer()
    payload = _payload()
    signed = signer.sign(payload, now_ms=200).as_transport()
    assert fixture["canonical_payload_b64"] == base64.b64encode(__import__("prophet_sdk").resolver_v2.canonical_json_bytes(payload)).decode()
    assert fixture["signing_bytes_b64"] == base64.b64encode(attestation_signing_bytes(payload)).decode()
    assert fixture["public_key"] == signer.public_key
    assert fixture["signature_hex"] == signed["signature_hex"]


def test_source_result_freshness_uses_rc42_inclusive_expiry_boundary():
    assert _payload(now_ms=199)["valid_until_ms"] == "200"
    assert _payload(now_ms=200)["valid_until_ms"] == "200"
    with pytest.raises(VerifierAttestationError):
        _payload(now_ms=201)


def test_attestation_rejects_future_acquisition_and_excessive_ttl():
    signer = _signer()
    future = _payload(now_ms=200)
    future["acquired_at_ms"] = "6000"
    future["valid_until_ms"] = "6100"
    future["job_id"] = settlement_authorization_job_id({key: future[key] for key in ("cluster_genesis_hash", "program_id", "market", "resolver_definition_hash", "evidence_hash", "proof_hash", "public_inputs_hash")})
    future_signed = signer.sign(future, now_ms=6000).as_transport()
    with pytest.raises(VerifierAttestationError):
        verify_attestation(future_signed, expected_verifier_id=signer.verifier_id, expected_verifier_version=signer.verifier_version, expected_verifier_implementation_digest=signer.verifier_implementation_digest, expected_public_key=signer.public_key, now_ms=200)

    excessive = _payload(now_ms=200)
    excessive["valid_until_ms"] = str(int(excessive["acquired_at_ms"]) + 3_600_001)
    with pytest.raises(VerifierAttestationError):
        signer.sign(excessive, now_ms=200)


@pytest.mark.parametrize("field,value", [
    ("verifier_id", "prophet.verifier.runtime.b"),
    ("verifier_version", "2.0.1"),
    ("verifier_implementation_digest", H(9)),
    ("cluster_genesis_hash", H(9)),
    ("program_id", MARKET),
    ("market", PROGRAM),
    ("resolver_definition_hash", H(9)),
    ("evidence_hash", H(9)),
    ("proof_hash", H(9)),
    ("public_inputs_hash", H(9)),
    ("job_id", H(9)),
])
def test_frozen_signature_rejects_each_security_binding_mutation(field, value):
    signed = _signer().sign(_payload(), now_ms=200).as_transport()
    signed["payload"][field] = value
    with pytest.raises(VerifierAttestationError):
        verify_attestation(signed, expected_verifier_id="prophet.verifier.runtime.a", expected_verifier_version="2.0.0", expected_verifier_implementation_digest=H(3), expected_public_key=_signer().public_key, now_ms=200)


def test_frozen_one_byte_canonical_payload_mutation_rejects_original_signature():
    fixture = json.loads((__import__("pathlib").Path(__file__).parent / "fixtures" / "verifier_attestation_v1.json").read_text())
    mutated_payload = __import__("prophet_sdk").resolver_v2.parse_canonical_json(base64.b64decode(fixture["one_byte_payload_mutation_b64"]))
    assert __import__("prophet_sdk").resolver_v2.canonical_json_bytes(mutated_payload) == base64.b64decode(fixture["one_byte_payload_mutation_b64"])
    with pytest.raises(VerifierAttestationError):
        verify_attestation({"payload": mutated_payload, "signature_hex": fixture["signature_hex"], "public_key": fixture["public_key"]}, expected_verifier_id="prophet.verifier.runtime.a", expected_verifier_version="2.0.0", expected_verifier_implementation_digest=H(3), expected_public_key=fixture["public_key"], now_ms=200)


def test_coordinator_job_id_is_not_a_settlement_authorization_job_id():
    from src.resolution_coordinator_store import _job_id as coordinator_job_id

    payload = _payload()
    workflow_id = coordinator_job_id(market=payload["market"], definition_hash=payload["resolver_definition_hash"], evidence_hash=payload["evidence_hash"], verifier_a=_result()["verifier"], verifier_b={**_result()["verifier"], "adapter_id": "prophet.verifier.runtime.b"})
    assert workflow_id != settlement_authorization_job_id({key: payload[key] for key in ("cluster_genesis_hash", "program_id", "market", "resolver_definition_hash", "evidence_hash", "proof_hash", "public_inputs_hash")})
    with pytest.raises(VerifierAttestationError):
        validate_attestation_payload({**payload, "job_id": workflow_id}, now_ms=200)
