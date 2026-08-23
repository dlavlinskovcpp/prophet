"""Canonical signed verifier attestations for the off-chain authorization plane.

These attestations are intentionally separate from Resolver V2 objects and from
the frozen PROPHET_RESOLVE_V2 settlement message.  They authenticate which
verifier produced a verified result; they do not authorize settlement.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


ATTESTATION_SCHEMA = "prophet.verifier-attestation.v1"
ATTESTATION_VERSION = "1"
ATTESTATION_DOMAIN = b"PROPHET_VERIFIER_ATTESTATION_V1\0"
JOB_ID_DOMAIN = b"PROPHET_SETTLEMENT_JOB_V1\0"
_FIELDS = frozenset((
    "attestation_schema", "attestation_version", "verifier_id", "verifier_version",
    "verifier_implementation_digest", "job_id", "cluster_genesis_hash", "program_id",
    "market", "resolver_definition_hash", "evidence_hash", "outcome", "proof_hash",
    "public_inputs_hash", "acquired_at_ms", "valid_until_ms",
))
_JOB_FIELDS = (
    "cluster_genesis_hash", "program_id", "market", "resolver_definition_hash",
    "evidence_hash", "proof_hash", "public_inputs_hash",
)


class VerifierAttestationError(ValueError):
    """Canonical attestation validation or cryptographic verification failed."""


def _fail(message: str) -> None:
    raise VerifierAttestationError(message)


def _hex32(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        _fail(f"{field}_invalid")
    try:
        if bytes.fromhex(value).hex() != value:
            raise ValueError
    except ValueError:
        _fail(f"{field}_invalid")
    return value


def _pubkey(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{field}_invalid")
    try:
        if str(Pubkey.from_string(value)) != value:
            raise ValueError
    except Exception:
        _fail(f"{field}_invalid")
    return value


def _uint(value: Any, field: str) -> int:
    if not isinstance(value, str) or not value or (value != "0" and value.startswith("0")) or not value.isdigit():
        _fail(f"{field}_invalid")
    number = int(value)
    if number > (2**64 - 1):
        _fail(f"{field}_invalid")
    return number


def canonical_job_payload(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(_JOB_FIELDS):
        _fail("job_binding_shape_invalid")
    payload = {field: value[field] for field in _JOB_FIELDS}
    _hex32(payload["cluster_genesis_hash"], "cluster_genesis_hash")
    _pubkey(payload["program_id"], "program_id")
    _pubkey(payload["market"], "market")
    for field in ("resolver_definition_hash", "evidence_hash", "proof_hash", "public_inputs_hash"):
        _hex32(payload[field], field)
    try:
        resolver_v2.canonical_json_bytes(payload)
    except resolver_v2.ResolverV2Error as exc:
        raise VerifierAttestationError("job_binding_noncanonical") from exc
    return payload


def settlement_authorization_job_id(value: Mapping[str, Any]) -> str:
    """The sole settlement-authorization identity formula shared by verifiers and future signers."""
    payload = canonical_job_payload(value)
    return hashlib.sha256(JOB_ID_DOMAIN + resolver_v2.canonical_json_bytes(payload)).hexdigest()


# The payload field remains the frozen wire name ``job_id``. This compatibility
# alias is not a second formula; boundary-facing code uses the explicit name.
def settlement_job_id(value: Mapping[str, Any]) -> str:
    return settlement_authorization_job_id(value)


def validate_attestation_payload(value: Mapping[str, Any], *, now_ms: Optional[int] = None) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        _fail("attestation_payload_shape_invalid")
    payload = dict(value)
    if payload["attestation_schema"] != ATTESTATION_SCHEMA or payload["attestation_version"] != ATTESTATION_VERSION:
        _fail("attestation_schema_unsupported")
    for field in ("verifier_id", "verifier_version"):
        if not isinstance(payload[field], str) or not payload[field]:
            _fail(f"{field}_invalid")
    _hex32(payload["verifier_implementation_digest"], "verifier_implementation_digest")
    _hex32(payload["job_id"], "job_id")
    _hex32(payload["cluster_genesis_hash"], "cluster_genesis_hash")
    _pubkey(payload["program_id"], "program_id")
    _pubkey(payload["market"], "market")
    for field in ("resolver_definition_hash", "evidence_hash", "proof_hash", "public_inputs_hash"):
        _hex32(payload[field], field)
    if payload["outcome"] not in ("YES", "NO", "INVALID"):
        _fail("outcome_invalid")
    acquired = _uint(payload["acquired_at_ms"], "acquired_at_ms")
    valid_until = _uint(payload["valid_until_ms"], "valid_until_ms")
    if valid_until <= acquired:
        _fail("attestation_validity_invalid")
    if payload["job_id"] != settlement_authorization_job_id({field: payload[field] for field in _JOB_FIELDS}):
        _fail("attestation_job_id_mismatch")
    try:
        canonical = resolver_v2.canonical_json_bytes(payload)
    except resolver_v2.ResolverV2Error as exc:
        raise VerifierAttestationError("attestation_payload_noncanonical") from exc
    if now_ms is not None and valid_until < now_ms:
        _fail("attestation_expired")
    # Ensures callers cannot use values that are accepted only after normalization.
    if resolver_v2.parse_canonical_json(canonical) != payload:
        _fail("attestation_payload_noncanonical")
    return payload


def attestation_signing_bytes(payload: Mapping[str, Any]) -> bytes:
    canonical = resolver_v2.canonical_json_bytes(validate_attestation_payload(payload))
    if len(canonical) > 0xFFFFFFFF:
        _fail("attestation_payload_too_large")
    return ATTESTATION_DOMAIN + len(canonical).to_bytes(4, "little") + canonical


@dataclass(frozen=True)
class SignedVerifierAttestation:
    payload: Mapping[str, str]
    signature_hex: str
    public_key: str

    def as_transport(self) -> dict[str, Any]:
        return {"payload": dict(self.payload), "signature_hex": self.signature_hex, "public_key": self.public_key}


@dataclass(frozen=True)
class VerifierAttestationSigner:
    verifier_id: str
    verifier_version: str
    verifier_implementation_digest: str
    keypair: Keypair

    @property
    def public_key(self) -> str:
        return str(self.keypair.pubkey())

    @classmethod
    def from_environment(cls, *, verifier_id: str, verifier_version: str, verifier_implementation_digest: str, expected_public_key: str, private_key_env: str) -> "VerifierAttestationSigner":
        raw = os.getenv(private_key_env, "")
        if not raw:
            _fail("verifier_attestation_private_key_missing")
        try:
            keypair = Keypair.from_base58_string(raw)
        except Exception as exc:
            raise VerifierAttestationError("verifier_attestation_private_key_invalid") from exc
        signer = cls(verifier_id, verifier_version, verifier_implementation_digest, keypair)
        if signer.public_key != _pubkey(expected_public_key, "expected_public_key"):
            _fail("verifier_attestation_public_key_mismatch")
        return signer

    def sign(self, payload: Mapping[str, Any], *, now_ms: int) -> SignedVerifierAttestation:
        """Sign only an attestation still valid at the explicit issuance time."""
        canonical = validate_attestation_payload(payload, now_ms=now_ms)
        expected = (self.verifier_id, self.verifier_version, self.verifier_implementation_digest)
        actual = (canonical["verifier_id"], canonical["verifier_version"], canonical["verifier_implementation_digest"])
        if actual != expected:
            _fail("attestation_signer_identity_mismatch")
        return SignedVerifierAttestation(canonical, bytes(self.keypair.sign_message(attestation_signing_bytes(canonical))).hex(), self.public_key)


def verify_attestation(value: Mapping[str, Any], *, expected_verifier_id: str, expected_verifier_version: str, expected_verifier_implementation_digest: str, expected_public_key: str, now_ms: Optional[int] = None) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"payload", "signature_hex", "public_key"}:
        _fail("signed_attestation_shape_invalid")
    payload = validate_attestation_payload(value["payload"], now_ms=now_ms)
    expected = (expected_verifier_id, expected_verifier_version, expected_verifier_implementation_digest)
    actual = (payload["verifier_id"], payload["verifier_version"], payload["verifier_implementation_digest"])
    if actual != expected:
        _fail("attestation_verifier_identity_mismatch")
    public_key = _pubkey(value["public_key"], "attestation_public_key")
    if public_key != _pubkey(expected_public_key, "expected_public_key"):
        _fail("attestation_public_key_mismatch")
    signature_hex = value["signature_hex"]
    if not isinstance(signature_hex, str) or len(signature_hex) != 128:
        _fail("attestation_signature_invalid")
    try:
        signature = Signature.from_bytes(bytes.fromhex(signature_hex))
        valid = signature.verify(Pubkey.from_string(public_key), attestation_signing_bytes(payload))
    except Exception as exc:
        raise VerifierAttestationError("attestation_signature_invalid") from exc
    if not valid:
        _fail("attestation_signature_invalid")
    return payload


def payload_from_verification_result(
    result: Mapping[str, Any],
    *,
    cluster_genesis_hash: str,
    program_id: str,
    market: str,
    proof_hash: str,
    public_inputs_hash: str,
    now_ms: int,
) -> dict[str, str]:
    """Build the only attestation payload from a verified Resolver V2 result."""
    try:
        verified = resolver_v2.validate_verification_result(result, now_ms=now_ms)
        facts = resolver_v2.parse_canonical_json(bytes.fromhex(verified["verified_facts_hex"]))
    except (ValueError, resolver_v2.ResolverV2Error) as exc:
        raise VerifierAttestationError("verification_result_invalid") from exc
    if verified["result"] != "VERIFIED" or facts.get("status") != "VERIFIED" or facts.get("outcome") not in ("YES", "NO", "INVALID"):
        _fail("verification_result_not_attestable")
    verifier = verified["verifier"]
    job_binding = {
        "cluster_genesis_hash": cluster_genesis_hash,
        "program_id": program_id,
        "market": market,
        "resolver_definition_hash": verified["definition_hash"],
        "evidence_hash": verified["evidence_hash"],
        "proof_hash": proof_hash,
        "public_inputs_hash": public_inputs_hash,
    }
    job_id = settlement_authorization_job_id(job_binding)
    payload = {
        "attestation_schema": ATTESTATION_SCHEMA,
        "attestation_version": ATTESTATION_VERSION,
        "verifier_id": verifier["adapter_id"],
        "verifier_version": verifier["adapter_version"],
        "verifier_implementation_digest": verifier["implementation_digest"],
        "job_id": job_id,
        **job_binding,
        "outcome": facts["outcome"],
        "acquired_at_ms": verified["observed_at_ms"],
        "valid_until_ms": verified["valid_until_ms"],
    }
    return validate_attestation_payload(payload, now_ms=now_ms)
