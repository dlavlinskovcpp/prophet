"""Pure G1 primitives for signer admission grants.

These values are deliberately data-only: this module has no HTTP, Vault, RPC,
journal, or settlement-signing authority.  G2/G3 own replay and admission.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

import rfc8785
from solders.pubkey import Pubkey
from solders.signature import Signature

from .verifier_attestation import (
    ATTESTATION_SCHEMA,
    ATTESTATION_VERSION,
    VerifierAttestationError,
    validate_attestation_payload,
)


AUTHORIZATION_SCHEMA = "PROPHET_SETTLEMENT_AUTHORIZATION_V1"
AUTHORIZATION_VERSION = "1"
REQUEST_BINDING_SCHEMA = "PROPHET_SIGNER_ADMISSION_REQUEST_BINDING_V1"
REQUEST_BINDING_DOMAIN = b"PROPHET_SIGNER_ADMISSION_REQUEST_BINDING_V1\0"
GRANT_SCHEMA = "PROPHET_SIGNER_ADMISSION_GRANT_V1"
GRANT_DOMAIN = b"PROPHET_SIGNER_ADMISSION_GRANT_V1\0"
GRANT_SIGNATURE_SCHEMA = "PROPHET_SIGNER_ADMISSION_GRANT_SIGNATURE_V1"
_MAX_BODY = 65_536
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_HEX16 = re.compile(r"^[0-9a-f]{32}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX128 = re.compile(r"^[0-9a-fA-F]{128}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_REQUEST_FIELDS = frozenset(("schema", "version", "cluster_genesis_hash", "program_id", "market", "verifier_a_attestation", "verifier_b_attestation"))
_ENVELOPE_FIELDS = frozenset(("payload", "signature_hex", "public_key"))
_GRANT_FIELDS = frozenset(("schema", "version", "grant_id", "environment", "git_sha", "evidence_set_id", "acceptance_run_id", "signer_role", "signer_service_id", "admission_request_sha256", "issuer_id", "key_id", "issued_at", "valid_until"))
_SIGNATURE_FIELDS = frozenset(("schema", "version", "algorithm", "issuer_id", "key_id", "signed_payload_sha256", "signature"))


class AdmissionGrantError(ValueError):
    """Malformed request/grant or failed cryptographic context check."""


def _fail(code: str) -> None:
    raise AdmissionGrantError(code)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_key")
        result[key] = value
    return result


def _no_float(_: str) -> None:
    _fail("json_float_forbidden")


def _no_constant(_: str) -> None:
    _fail("json_constant_forbidden")


def decode_strict_json(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or len(raw) > _MAX_BODY:
        _fail("request_body_invalid")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise AdmissionGrantError("strict_json_invalid") from exc
    _check_json_shape(value, depth=1)
    return value


def _check_json_shape(value: Any, *, depth: int) -> None:
    """Reject arrays and excessive object nesting before schema semantics."""
    if isinstance(value, list):
        _fail("json_array_forbidden")
    if isinstance(value, dict):
        if depth > 3:
            _fail("json_depth_exceeded")
        for child in value.values():
            _check_json_shape(child, depth=depth + 1)


def _object(value: Any, fields: frozenset[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(code)
    return value


def _hex(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail(code)
    return value


def _pubkey(value: Any, code: str) -> str:
    if not isinstance(value, str):
        _fail(code)
    try:
        if str(Pubkey.from_string(value)) != value:
            raise ValueError
    except Exception as exc:
        raise AdmissionGrantError(code) from exc
    return value


def _uint_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value or (value != "0" and value.startswith("0")) or not value.isdigit() or int(value) > 2**64 - 1:
        _fail(code)
    return value


@dataclass(frozen=True)
class SignedVerifierAttestationV1:
    payload: Mapping[str, str]
    signature_hex: str
    public_key: str

    @classmethod
    def from_mapping(cls, value: Any) -> "SignedVerifierAttestationV1":
        row = _object(value, _ENVELOPE_FIELDS, "attestation_envelope_invalid")
        try:
            payload = validate_attestation_payload(row["payload"])
        except VerifierAttestationError as exc:
            raise AdmissionGrantError("attestation_payload_invalid") from exc
        signature = _hex(row["signature_hex"], _HEX128, "attestation_signature_invalid")
        return cls(payload, signature, _pubkey(row["public_key"], "attestation_public_key_invalid"))

    def as_mapping(self) -> dict[str, Any]:
        return {"payload": dict(self.payload), "signature_hex": self.signature_hex, "public_key": self.public_key}


@dataclass(frozen=True)
class StrictSignerAuthorizationRequestV1:
    schema: str
    version: str
    cluster_genesis_hash: str
    program_id: str
    market: str
    verifier_a_attestation: SignedVerifierAttestationV1
    verifier_b_attestation: SignedVerifierAttestationV1

    @classmethod
    def from_mapping(cls, value: Any) -> "StrictSignerAuthorizationRequestV1":
        row = _object(value, _REQUEST_FIELDS, "authorization_request_invalid")
        if row["schema"] != AUTHORIZATION_SCHEMA or row["version"] != AUTHORIZATION_VERSION:
            _fail("authorization_schema_invalid")
        return cls(
            AUTHORIZATION_SCHEMA, AUTHORIZATION_VERSION,
            _hex(row["cluster_genesis_hash"], _HEX32, "request_genesis_invalid"),
            _pubkey(row["program_id"], "request_program_invalid"),
            _pubkey(row["market"], "request_market_invalid"),
            SignedVerifierAttestationV1.from_mapping(row["verifier_a_attestation"]),
            SignedVerifierAttestationV1.from_mapping(row["verifier_b_attestation"]),
        )

    def as_mapping(self) -> dict[str, Any]:
        return {"schema": self.schema, "version": self.version, "cluster_genesis_hash": self.cluster_genesis_hash, "program_id": self.program_id, "market": self.market, "verifier_a_attestation": self.verifier_a_attestation.as_mapping(), "verifier_b_attestation": self.verifier_b_attestation.as_mapping()}



def parse_strict_signer_authorization_request(raw: bytes) -> StrictSignerAuthorizationRequestV1:
    return StrictSignerAuthorizationRequestV1.from_mapping(decode_strict_json(raw))


def admission_request_binding_object(request: StrictSignerAuthorizationRequestV1) -> dict[str, Any]:
    if not isinstance(request, StrictSignerAuthorizationRequestV1):
        _fail("strict_request_required")
    return {"schema": REQUEST_BINDING_SCHEMA, "version": 1, "operation": "authorize_and_sign", "request": request.as_mapping()}


def _preimage(domain: bytes, value: Mapping[str, Any]) -> tuple[bytes, bytes]:
    try:
        jcs = rfc8785.dumps(dict(value))
    except Exception as exc:
        raise AdmissionGrantError("jcs_invalid") from exc
    if len(jcs) > 0xFFFFFFFF:
        _fail("jcs_too_large")
    return jcs, domain + struct.pack("<I", len(jcs)) + jcs


def admission_request_binding(request: StrictSignerAuthorizationRequestV1) -> tuple[bytes, bytes, str]:
    jcs, preimage = _preimage(REQUEST_BINDING_DOMAIN, admission_request_binding_object(request))
    return jcs, preimage, hashlib.sha256(preimage).hexdigest()


def _time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        _fail(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AdmissionGrantError(code) from exc


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail(code)
    return value


@dataclass(frozen=True)
class AdmissionGrantV1:
    values: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> "AdmissionGrantV1":
        row = _object(value, _GRANT_FIELDS, "admission_grant_shape_invalid")
        if row["schema"] != GRANT_SCHEMA or isinstance(row["version"], bool) or row["version"] != 1:
            _fail("admission_grant_schema_invalid")
        _hex(row["grant_id"], _HEX16, "grant_id_invalid")
        _identifier(row["environment"], "environment_invalid")
        _hex(row["git_sha"], _HEX40, "git_sha_invalid")
        for field in ("evidence_set_id", "signer_service_id", "issuer_id", "key_id"):
            _identifier(row[field], f"{field}_invalid")
        _hex(row["acceptance_run_id"], _HEX16, "acceptance_run_id_invalid")
        if row["signer_role"] not in ("A", "B"):
            _fail("signer_role_invalid")
        _hex(row["admission_request_sha256"], _HEX32, "admission_request_sha256_invalid")
        issued, until = _time(row["issued_at"], "issued_at_invalid"), _time(row["valid_until"], "valid_until_invalid")
        if issued >= until or until - issued > timedelta(minutes=60):
            _fail("grant_interval_invalid")
        return cls(dict(row))

    def as_mapping(self) -> dict[str, Any]:
        return dict(self.values)


@dataclass(frozen=True)
class AdmissionGrantSignatureV1:
    values: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> "AdmissionGrantSignatureV1":
        row = _object(value, _SIGNATURE_FIELDS, "grant_signature_shape_invalid")
        if row["schema"] != GRANT_SIGNATURE_SCHEMA or isinstance(row["version"], bool) or row["version"] != 1 or row["algorithm"] != "ed25519":
            _fail("grant_signature_schema_invalid")
        _identifier(row["issuer_id"], "issuer_id_invalid"); _identifier(row["key_id"], "key_id_invalid")
        _hex(row["signed_payload_sha256"], _HEX32, "signed_payload_sha256_invalid")
        _hex(row["signature"], _HEX128, "grant_signature_invalid")
        return cls(dict(row))


@dataclass(frozen=True)
class AdmissionIssuerKeyV1:
    key_id: str
    issuer_id: str
    signer_role: str
    public_key: str
    valid_from: str
    valid_until: str

    def __post_init__(self) -> None:
        _identifier(self.key_id, "issuer_key_id_invalid"); _identifier(self.issuer_id, "issuer_id_invalid")
        if self.signer_role not in ("A", "B"): _fail("issuer_role_invalid")
        _pubkey(self.public_key, "issuer_public_key_invalid")
        if _time(self.valid_from, "issuer_valid_from_invalid") >= _time(self.valid_until, "issuer_valid_until_invalid"):
            _fail("issuer_key_interval_invalid")


@dataclass(frozen=True)
class AdmissionGrantContext:
    signer_role: str
    signer_service_id: str
    environment: str
    git_sha: str
    evidence_set_id: str
    acceptance_run_id: str

    def __post_init__(self) -> None:
        if self.signer_role not in ("A", "B"): _fail("context_signer_role_invalid")
        _identifier(self.signer_service_id, "context_service_invalid"); _identifier(self.environment, "context_environment_invalid")
        _hex(self.git_sha, _HEX40, "context_git_sha_invalid"); _identifier(self.evidence_set_id, "context_evidence_set_invalid"); _hex(self.acceptance_run_id, _HEX16, "context_run_id_invalid")


@dataclass(frozen=True)
class VerifiedAdmissionGrant:
    """Audit facts only; G2/G3 must not treat this as admission authority."""
    grant_id: str
    issuer_id: str
    key_id: str
    signer_role: str
    admission_request_sha256: str


def verify_admission_grant(*, unsigned_grant: Any, signature_envelope: Any, request: StrictSignerAuthorizationRequestV1, context: AdmissionGrantContext, issuer_keys: Sequence[AdmissionIssuerKeyV1], trusted_now: datetime) -> VerifiedAdmissionGrant:
    grant, envelope = AdmissionGrantV1.from_mapping(unsigned_grant), AdmissionGrantSignatureV1.from_mapping(signature_envelope)
    if trusted_now.tzinfo is None: _fail("trusted_now_timezone_required")
    now = trusted_now.astimezone(timezone.utc)
    _, preimage = _preimage(GRANT_DOMAIN, grant.as_mapping())
    digest = hashlib.sha256(preimage).hexdigest()
    if envelope.values["signed_payload_sha256"] != digest or envelope.values["issuer_id"] != grant.values["issuer_id"] or envelope.values["key_id"] != grant.values["key_id"]:
        _fail("grant_envelope_binding_invalid")
    _, _, request_digest = admission_request_binding(request)
    expected = {"signer_role": context.signer_role, "signer_service_id": context.signer_service_id, "environment": context.environment, "git_sha": context.git_sha, "evidence_set_id": context.evidence_set_id, "acceptance_run_id": context.acceptance_run_id, "admission_request_sha256": request_digest}
    if any(grant.values[field] != value for field, value in expected.items()): _fail("grant_context_mismatch")
    issued, until = _time(grant.values["issued_at"], "issued_at_invalid"), _time(grant.values["valid_until"], "valid_until_invalid")
    if issued > now + timedelta(minutes=5) or now >= until: _fail("grant_temporal_invalid")
    key = next((item for item in issuer_keys if item.key_id == grant.values["key_id"] and item.issuer_id == grant.values["issuer_id"] and item.signer_role == context.signer_role), None)
    if key is None: _fail("issuer_key_untrusted")
    start, end = _time(key.valid_from, "issuer_valid_from_invalid"), _time(key.valid_until, "issuer_valid_until_invalid")
    if not (start <= issued < until <= end and start <= now < end): _fail("issuer_key_temporal_invalid")
    try:
        valid = Signature.from_bytes(bytes.fromhex(envelope.values["signature"])).verify(Pubkey.from_string(key.public_key), preimage)
    except Exception as exc:
        raise AdmissionGrantError("grant_signature_invalid") from exc
    if not valid: _fail("grant_signature_invalid")
    return VerifiedAdmissionGrant(grant.values["grant_id"], grant.values["issuer_id"], grant.values["key_id"], grant.values["signer_role"], request_digest)


def validate_admission_issuer_key_isolation(*, issuer_a: str, issuer_b: str, existing_public_keys: Sequence[str] = ()) -> None:
    try:
        a, b = bytes(Pubkey.from_string(issuer_a)), bytes(Pubkey.from_string(issuer_b))
        existing = {bytes(Pubkey.from_string(item)) for item in existing_public_keys}
    except Exception as exc:
        raise AdmissionGrantError("issuer_key_invalid") from exc
    if a == b or a in existing or b in existing: _fail("issuer_key_alias")
