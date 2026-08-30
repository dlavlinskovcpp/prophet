import hashlib
import json
from datetime import datetime, timezone

import pytest
import rfc8785
from solders.keypair import Keypair

from src.signer_admission_grant import (
    AdmissionGrantContext,
    AdmissionGrantError,
    AdmissionIssuerKeyV1,
    GRANT_DOMAIN,
    GRANT_SCHEMA,
    GRANT_SIGNATURE_SCHEMA,
    REQUEST_BINDING_DOMAIN,
    StrictSignerAuthorizationRequestV1,
    admission_request_binding,
    admission_request_binding_object,
    parse_strict_signer_authorization_request,
    validate_admission_issuer_key_isolation,
    verify_admission_grant,
)
from tests.test_signer_authorization import fixture


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def _request():
    request, *_ = fixture()
    return request


def _raw(value):
    return json.dumps(value, separators=(",", ":")).encode()


def _context(request):
    _, _, digest = admission_request_binding(request)
    return AdmissionGrantContext("A", "signer-a", "public-devnet", "a" * 40, "evidence-001", "b" * 32), digest


def _signed_grant(request, *, key=None, mutate=None):
    key = key or Keypair.from_seed(bytes(range(32)))
    context, digest = _context(request)
    grant = {"schema": GRANT_SCHEMA, "version": 1, "grant_id": "c" * 32, "environment": context.environment, "git_sha": context.git_sha, "evidence_set_id": context.evidence_set_id, "acceptance_run_id": context.acceptance_run_id, "signer_role": "A", "signer_service_id": "signer-a", "admission_request_sha256": digest, "issuer_id": "issuer-a", "key_id": "key-a", "issued_at": "2026-08-27T11:30:00Z", "valid_until": "2026-08-27T12:30:00Z"}
    if mutate:
        mutate(grant)
    jcs = rfc8785.dumps(grant)
    preimage = GRANT_DOMAIN + len(jcs).to_bytes(4, "little") + jcs
    envelope = {"schema": GRANT_SIGNATURE_SCHEMA, "version": 1, "algorithm": "ed25519", "issuer_id": grant["issuer_id"], "key_id": grant["key_id"], "signed_payload_sha256": hashlib.sha256(preimage).hexdigest(), "signature": bytes(key.sign_message(preimage)).hex()}
    trusted = AdmissionIssuerKeyV1("key-a", "issuer-a", "A", str(key.pubkey()), "2026-08-27T11:00:00Z", "2026-08-27T13:00:00Z")
    return grant, envelope, context, [trusted]


def test_strict_request_round_trip_and_transport_equivalence():
    request = _request()
    first = parse_strict_signer_authorization_request(_raw(request))
    reordered = {key: request[key] for key in reversed(tuple(request))}
    second = parse_strict_signer_authorization_request(b" \n" + _raw(reordered) + b"\t")
    assert first.as_mapping() == second.as_mapping()
    assert admission_request_binding(first)[2] == admission_request_binding(second)[2]
    jcs, preimage, digest = admission_request_binding(first)
    assert preimage == REQUEST_BINDING_DOMAIN + len(jcs).to_bytes(4, "little") + jcs
    assert digest == hashlib.sha256(preimage).hexdigest()
    assert admission_request_binding_object(first)["operation"] == "authorize_and_sign"


@pytest.mark.parametrize("raw", (
    b'{"schema":"x","schema":"x"}',
    b'{"schema":NaN}',
    b'{"schema":1.5}',
    b'{"schema":true}',
    b'[]',
    b'{"schema":"PROPHET_SETTLEMENT_AUTHORIZATION_V1","version":"1","cluster_genesis_hash":"' + b"00" * 32 + b'","program_id":"11111111111111111111111111111111","market":"11111111111111111111111111111111","verifier_a_attestation":[],"verifier_b_attestation":[]}',
), ids=("duplicate", "nan", "float", "boolean", "array", "nested_array"))
def test_strict_request_rejects_non_frozen_json_domain(raw):
    with pytest.raises(AdmissionGrantError):
        parse_strict_signer_authorization_request(raw)


def test_nested_duplicate_rejects_before_typed_attestation():
    raw = _raw(_request()).replace(b'"verifier_id":"a"', b'"verifier_id":"a","verifier_id":"a"', 1)
    with pytest.raises(AdmissionGrantError, match="strict_json_invalid"):
        parse_strict_signer_authorization_request(raw)


def test_each_semantic_leaf_binds_request_digest():
    first = StrictSignerAuthorizationRequestV1.from_mapping(_request())
    changed = first.as_mapping()
    changed["verifier_a_attestation"]["payload"]["evidence_hash"] = "f" * 64
    # The mutation invalidates the signed attestation, which is correctly
    # rejected before it can become a different admission binding.
    with pytest.raises(AdmissionGrantError):
        StrictSignerAuthorizationRequestV1.from_mapping(changed)


def test_valid_grant_verifies_direct_preimage_and_exact_context():
    request = StrictSignerAuthorizationRequestV1.from_mapping(_request())
    grant, envelope, context, keys = _signed_grant(request)
    result = verify_admission_grant(unsigned_grant=grant, signature_envelope=envelope, request=request, context=context, issuer_keys=keys, trusted_now=NOW)
    assert result.grant_id == "c" * 32 and result.signer_role == "A"


@pytest.mark.parametrize("mutate", (
    lambda grant: grant.__setitem__("signer_role", "B"),
    lambda grant: grant.__setitem__("admission_request_sha256", "0" * 64),
    lambda grant: grant.__setitem__("valid_until", "2026-08-27T12:31:00Z"),
), ids=("role", "request_digest", "over_60_minutes"))
def test_grant_context_and_temporal_mutations_reject(mutate):
    request = StrictSignerAuthorizationRequestV1.from_mapping(_request())
    grant, envelope, context, keys = _signed_grant(request, mutate=mutate)
    with pytest.raises(AdmissionGrantError):
        verify_admission_grant(unsigned_grant=grant, signature_envelope=envelope, request=request, context=context, issuer_keys=keys, trusted_now=NOW)


def test_bad_signature_and_role_key_alias_reject():
    request = StrictSignerAuthorizationRequestV1.from_mapping(_request())
    grant, envelope, context, keys = _signed_grant(request)
    envelope["signature"] = "00" * 64
    with pytest.raises(AdmissionGrantError):
        verify_admission_grant(unsigned_grant=grant, signature_envelope=envelope, request=request, context=context, issuer_keys=keys, trusted_now=NOW)
    public = keys[0].public_key
    with pytest.raises(AdmissionGrantError, match="issuer_key_alias"):
        validate_admission_issuer_key_isolation(issuer_a=public, issuer_b=public)
    with pytest.raises(AdmissionGrantError, match="issuer_key_alias"):
        validate_admission_issuer_key_isolation(issuer_a=public, issuer_b=str(Keypair.from_seed(bytes(range(32, 64))).pubkey()), existing_public_keys=[public])
