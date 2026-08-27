"""Pure P0C3E1 operational-evidence verification.

This module accepts only explicit public inputs.  It deliberately has no HTTP,
Vault, RPC, journal, environment, or service-runtime capability.
"""
from __future__ import annotations

import base64
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


BASELINE_GIT_SHA = "af50c01f562b6cb1a0851fa0f59c45d820d595f8"
POLICY_SCHEMA = "PROPHET_OPERATED_SIGNER_TRUST_POLICY_V1"
EVIDENCE_SCHEMA = "PROPHET_OPERATED_SIGNER_EVIDENCE_V1"
EVIDENCE_SIGNATURE_SCHEMA = "PROPHET_OPERATED_SIGNER_EVIDENCE_SIGNATURE_V1"
PROVIDER_ATTESTATION_SCHEMA = "PROPHET_OPERATED_SIGNER_EVIDENCE_PROVIDER_ATTESTATION_V1"
RESULT_SCHEMA = "PROPHET_PROVIDER_VERIFICATION_RESULT_V1"
RESULT_V2_SCHEMA = "PROPHET_PROVIDER_VERIFICATION_RESULT_V2"
RESULT_SIGNATURE_SCHEMA = "PROPHET_PROVIDER_VERIFICATION_RESULT_SIGNATURE_V1"
R3C_POLICY_SCHEMA = "PROPHET_OPERATED_SIGNER_TRUST_POLICY_V2"
EVIDENCE_DOMAIN = b"PROPHET_OPERATED_SIGNER_EVIDENCE_V1\0"
RESULT_DOMAIN = b"PROPHET_PROVIDER_VERIFICATION_RESULT_V1\0"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_SECRET_FIELDS = frozenset(("vault_token", "admission_token", "rpc_api_key", "authorization", "private_key", "seed", "mnemonic", "raw_credential", "credential_value"))
_CLASSIFICATIONS = frozenset(("MACHINE_VERIFIED", "PROVIDER_ATTESTED", "VAULT_ADMIN_ATTESTED", "MANUAL_REVIEW_REQUIRED"))
_REQUIRED_CATEGORIES = frozenset(("host", "runtime", "vault", "vault_key", "rpc", "journal", "audit", "tls", "process"))
_R3C_ROLES = frozenset(("A", "B"))
_R3C_CATEGORIES = frozenset((
    "host_vm", "runtime_principal", "runtime_admin_domain",
    "vault_auth_principal", "vault_admin_domain", "vault_account_tenant",
    "vault_key_identity_version", "rpc_credential_principal", "rpc_provider",
    "rpc_account_project", "journal_storage", "audit_domain", "tls_ingress",
    "worker_reload_concurrency",
))
_R3C_PROVENANCE_KINDS = frozenset((
    "provider_result", "vault_admin_attestation", "machine_verified",
    "manual_review_permit",
))


class OperationalEvidenceError(ValueError):
    """A malformed or unauthorized public operational-evidence input."""


def _fail(code: str) -> None:
    raise OperationalEvidenceError(code)


def parse_json_strict(raw: str | bytes | bytearray) -> Any:
    """Parse JSON while rejecting duplicate object keys at every nesting level."""
    if not isinstance(raw, (str, bytes, bytearray)):
        _fail("json_input_invalid")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                _fail("duplicate_json_key")
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_fail("nonfinite_json_number")))
    except OperationalEvidenceError:
        raise
    except Exception as exc:
        raise OperationalEvidenceError("json_invalid") from exc


def _mapping(value: Any, fields: frozenset[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields or _SECRET_FIELDS.intersection(value):
        _fail(f"{name}_shape_invalid")
    return value


def _text(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum or not _ID.fullmatch(value):
        _fail(f"{name}_invalid")
    return value


def _hex(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        _fail(f"{name}_invalid")
    return value


def _integer(value: Any, name: str, *, positive: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (positive and value <= 0):
        _fail(f"{name}_invalid")
    return value


def _b64url(value: Any, name: str, length: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or any(c.isspace() for c in value) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        _fail(f"{name}_invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise OperationalEvidenceError(f"{name}_invalid") from exc
    if len(raw) != length or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        _fail(f"{name}_invalid")
    return raw


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        _fail(f"{name}_invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise OperationalEvidenceError(f"{name}_invalid") from exc


def parse_signer_role(value: Any) -> str:
    """Parse the closed R3C signer-role vocabulary without normalization."""
    if not isinstance(value, str) or value not in _R3C_ROLES:
        _fail("r3c_signer_role_invalid")
    return value


def parse_evidence_category(value: Any) -> str:
    """Parse the closed R3C evidence-category vocabulary."""
    if not isinstance(value, str) or value not in _R3C_CATEGORIES:
        _fail("r3c_evidence_category_invalid")
    return value


@dataclass(frozen=True)
class AuthorizationEvidenceItem:
    signer_role: str
    evidence_category: str
    artifact_id: str
    raw_artifact_sha256: str
    redacted_artifact_sha256: str
    provenance_kind: str
    provenance_ref: str


_R3C_EVIDENCE_ITEM_FIELDS = frozenset((
    "signer_role", "evidence_category", "artifact_id", "raw_artifact_sha256",
    "redacted_artifact_sha256", "provenance_kind", "provenance_ref",
))


def parse_authorization_evidence_item(value: Any) -> AuthorizationEvidenceItem:
    """Strictly parse one non-authorizing, role-local R3C evidence item."""
    row = _mapping(value, _R3C_EVIDENCE_ITEM_FIELDS, "r3c_evidence_item")
    role = parse_signer_role(row["signer_role"])
    category = parse_evidence_category(row["evidence_category"])
    artifact_id = _text(row["artifact_id"], "r3c_artifact_id")
    raw_hash = _hex(row["raw_artifact_sha256"], "r3c_raw_artifact_sha256")
    redacted_hash = _hex(row["redacted_artifact_sha256"], "r3c_redacted_artifact_sha256")
    if not isinstance(row["provenance_kind"], str) or row["provenance_kind"] not in _R3C_PROVENANCE_KINDS:
        _fail("r3c_provenance_kind_invalid")
    provenance_ref = _text(row["provenance_ref"], "r3c_provenance_ref")
    return AuthorizationEvidenceItem(role, category, artifact_id, raw_hash, redacted_hash, row["provenance_kind"], provenance_ref)


def parse_authorization_evidence_inventory(value: Any) -> tuple[AuthorizationEvidenceItem, ...]:
    """Validate the exact 2 x 14 non-authorizing R3C evidence inventory."""
    if not isinstance(value, list) or len(value) != len(_R3C_ROLES) * len(_R3C_CATEGORIES):
        _fail("r3c_evidence_inventory_size_invalid")
    items = tuple(parse_authorization_evidence_item(item) for item in value)
    pairs = {(item.signer_role, item.evidence_category) for item in items}
    expected = {(role, category) for role in _R3C_ROLES for category in _R3C_CATEGORIES}
    if pairs != expected:
        _fail("r3c_evidence_inventory_coverage_invalid")
    artifact_ids = [item.artifact_id for item in items]
    artifact_tuples = [(item.artifact_id, item.raw_artifact_sha256, item.redacted_artifact_sha256) for item in items]
    if len(set(artifact_ids)) != len(artifact_ids) or len(set(artifact_tuples)) != len(artifact_tuples):
        _fail("r3c_authorization_artifact_reuse")
    return items


def _jcs(value: Any, name: str) -> bytes:
    try:
        return rfc8785.dumps(value)
    except Exception as exc:
        raise OperationalEvidenceError(f"{name}_canonicalization_failed") from exc


def _preimage(domain: bytes, value: Any, name: str) -> tuple[bytes, bytes]:
    encoded = _jcs(value, name)
    if len(encoded) > 0xFFFFFFFF:
        _fail(f"{name}_too_large")
    preimage = domain + struct.pack("<I", len(encoded)) + encoded
    return encoded, preimage


def _verify_ed25519(public_key: str, signature: str, preimage: bytes, name: str) -> None:
    key = _b64url(public_key, f"{name}_public_key", 32)
    sig = _b64url(signature, f"{name}_signature", 64)
    try:
        if not Signature.from_bytes(sig).verify(Pubkey.from_bytes(key), preimage):
            _fail(f"{name}_signature_invalid")
    except OperationalEvidenceError:
        raise
    except Exception as exc:
        raise OperationalEvidenceError(f"{name}_signature_invalid") from exc


def evidence_preimage(unsigned_package: Mapping[str, Any]) -> bytes:
    _validate_unsigned(unsigned_package)
    return _preimage(EVIDENCE_DOMAIN, unsigned_package, "evidence")[1]


def result_preimage(unsigned_result: Mapping[str, Any]) -> bytes:
    _validate_result(unsigned_result)
    return _preimage(RESULT_DOMAIN, unsigned_result, "provider_result")[1]


@dataclass(frozen=True)
class ProviderResultVerificationKey:
    key_id: str
    issuer_identity: str
    public_key: str
    valid_from: str
    valid_until: str
    provider_policy_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.key_id, "provider_v2_key_id")
        _text(self.issuer_identity, "provider_v2_issuer_identity")
        _b64url(self.public_key, "provider_v2_public_key", 32)
        if _timestamp(self.valid_from, "provider_v2_key_valid_from") >= _timestamp(self.valid_until, "provider_v2_key_valid_until"):
            _fail("provider_v2_key_time_invalid")
        if not self.provider_policy_ids or len(set(self.provider_policy_ids)) != len(self.provider_policy_ids):
            _fail("provider_v2_key_policies_invalid")
        for policy_id in self.provider_policy_ids:
            _text(policy_id, "provider_v2_policy_id")


@dataclass(frozen=True)
class VerifiedProviderResultV2:
    signer_role: str
    evidence_category: str
    artifact_id: str
    raw_artifact_sha256: str
    redacted_artifact_sha256: str
    subject: tuple[tuple[str, str], ...]
    issuer_identity: str
    provider_policy_id: str
    verified_at: str
    valid_until: str


def _provider_subject(category: str, value: Any) -> Mapping[str, Any]:
    fields = _PROVIDER_SUBJECT_FIELDS.get(category)
    if fields is None:
        _fail("provider_v2_category_forbidden")
    row = _mapping(value, fields, "provider_v2_subject")
    for name, item in row.items():
        _text(item, f"provider_v2_{name}")
    return row


def _validate_result_v2(value: Any) -> Mapping[str, Any]:
    row = _mapping(value, _RESULT_V2_FIELDS, "provider_v2_result")
    if row["schema"] != RESULT_V2_SCHEMA or _integer(row["version"], "provider_v2_result_version") != 2 or row["result"] != "VERIFIED":
        _fail("provider_v2_schema_invalid")
    for field in ("provider_attestation_id", "issuer_identity", "subject_account_scope", "environment", "git_sha", "evidence_set_id", "artifact_id", "provider_policy_id"):
        _text(row[field], f"provider_v2_{field}")
    parse_signer_role(row["signer_role"])
    category = parse_evidence_category(row["evidence_category"])
    _provider_subject(category, row["subject"])
    _hex(row["raw_artifact_sha256"], "provider_v2_raw_artifact_sha256")
    _hex(row["redacted_artifact_sha256"], "provider_v2_redacted_artifact_sha256")
    _timestamp(row["issued_at"], "provider_v2_issued_at")
    _timestamp(row["verified_at"], "provider_v2_verified_at")
    _timestamp(row["valid_until"], "provider_v2_valid_until")
    return row


def result_v2_preimage(unsigned_result: Mapping[str, Any]) -> bytes:
    _validate_result_v2(unsigned_result)
    return _preimage(RESULT_DOMAIN, unsigned_result, "provider_v2_result")[1]


def verify_provider_result_v2(value: Any, *, keys: Sequence[ProviderResultVerificationKey], revoked_key_ids: Sequence[str], revoked_issuer_ids: Sequence[str], expected_signer_role: str, expected_evidence_category: str, expected_artifact_id: str, expected_raw_artifact_sha256: str, expected_redacted_artifact_sha256: str, expected_subject: Mapping[str, Any], package_valid_until: str, now: datetime) -> VerifiedProviderResultV2:
    """Verify only v2 cryptographic provenance; I4 derives authorization."""
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        _fail("provider_v2_trusted_time_invalid")
    row = _mapping(value, frozenset(("unsigned_result", "signature")), "signed_provider_v2_result")
    unsigned = _validate_result_v2(row["unsigned_result"])
    role = parse_signer_role(expected_signer_role)
    category = parse_evidence_category(expected_evidence_category)
    expected = (role, category, _text(expected_artifact_id, "provider_v2_expected_artifact_id"), _hex(expected_raw_artifact_sha256, "provider_v2_expected_raw_artifact_sha256"), _hex(expected_redacted_artifact_sha256, "provider_v2_expected_redacted_artifact_sha256"))
    actual = (unsigned["signer_role"], unsigned["evidence_category"], unsigned["artifact_id"], unsigned["raw_artifact_sha256"], unsigned["redacted_artifact_sha256"])
    if actual != expected:
        _fail("provider_v2_expected_context_invalid")
    if dict(_provider_subject(category, unsigned["subject"])) != dict(_provider_subject(category, expected_subject)):
        _fail("provider_v2_subject_binding_invalid")
    sig = _mapping(row["signature"], _RESULT_SIGNATURE_FIELDS, "provider_v2_signature")
    key_id = _text(sig["key_id"], "provider_v2_key_id")
    seen_ids: set[str] = set(); seen_keys: set[bytes] = set(); selected: ProviderResultVerificationKey | None = None
    for key in keys:
        if not isinstance(key, ProviderResultVerificationKey) or key.key_id in seen_ids:
            _fail("provider_v2_key_set_invalid")
        raw = _b64url(key.public_key, "provider_v2_public_key", 32)
        if raw in seen_keys:
            _fail("provider_v2_key_set_invalid")
        seen_ids.add(key.key_id); seen_keys.add(raw)
        if key.key_id == key_id:
            selected = key
    if sig["signature_schema"] != RESULT_SIGNATURE_SCHEMA or _integer(sig["signature_version"], "provider_v2_signature_version") != 1 or sig["algorithm"] != "ed25519":
        _fail("provider_v2_signature_schema_invalid")
    if selected is None or key_id in revoked_key_ids or selected.issuer_identity in revoked_issuer_ids:
        _fail("provider_v2_key_untrusted")
    if (unsigned["issuer_identity"] != selected.issuer_identity or unsigned["provider_policy_id"] not in selected.provider_policy_ids):
        _fail("provider_v2_issuer_policy_invalid")
    issued = _timestamp(unsigned["issued_at"], "provider_v2_issued_at")
    verified = _timestamp(unsigned["verified_at"], "provider_v2_verified_at")
    until = _timestamp(unsigned["valid_until"], "provider_v2_valid_until")
    package_until = _timestamp(package_valid_until, "provider_v2_package_valid_until")
    if (issued > verified or verified >= until or verified > now + timedelta(minutes=5) or now - verified > timedelta(hours=24) or until <= now or until - verified > timedelta(hours=72) or until > package_until or issued < _timestamp(selected.valid_from, "provider_v2_key_valid_from") or until > _timestamp(selected.valid_until, "provider_v2_key_valid_until")):
        _fail("provider_v2_time_invalid")
    _verify_ed25519(selected.public_key, sig["signature_bytes"], result_v2_preimage(unsigned), "provider_v2")
    return VerifiedProviderResultV2(unsigned["signer_role"], category, unsigned["artifact_id"], unsigned["raw_artifact_sha256"], unsigned["redacted_artifact_sha256"], tuple(sorted(unsigned["subject"].items())), unsigned["issuer_identity"], unsigned["provider_policy_id"], unsigned["verified_at"], unsigned["valid_until"])


@dataclass(frozen=True)
class StaticSignerBinding:
    signer_role: str
    signer_id: str
    signer_public_key: str
    service_config_fingerprint: str
    deployment_manifest_fingerprint: str

    def __post_init__(self) -> None:
        if self.signer_role not in ("A", "B"):
            _fail("static_signer_role_invalid")
        _text(self.signer_id, "static_signer_id")
        try:
            if str(Pubkey.from_string(self.signer_public_key)) != self.signer_public_key:
                raise ValueError
        except Exception as exc:
            raise OperationalEvidenceError("static_signer_public_key_invalid") from exc
        _hex(self.service_config_fingerprint, "static_service_config_fingerprint")
        _hex(self.deployment_manifest_fingerprint, "static_deployment_manifest_fingerprint")


@dataclass(frozen=True)
class VerifiedOperationalEvidence:
    schema: str
    version: int
    evidence_set_id: str
    environment: str
    git_sha: str
    trust_policy_sha256: str
    signed_payload_sha256: str
    operator_identity: str
    operator_key_id: str
    reviewer_identity: str
    reviewer_key_id: str
    signer_a_service_config_fingerprint: str
    signer_b_service_config_fingerprint: str
    signer_a_deployment_manifest_fingerprint: str
    signer_b_deployment_manifest_fingerprint: str
    independence_assertions: tuple[tuple[str, bool], ...]
    classifications: tuple[tuple[str, str], ...]
    generated_at: str
    valid_until: str


_POLICY_FIELDS = frozenset(("schema", "version", "policy_id", "policy_version", "environment", "release_scope", "allowed_algorithms", "deployment_operator_keys", "security_reviewer_keys", "vault_admin_issuers", "provider_issuer_policies", "p0c3e2_verification_keys", "revoked_key_ids", "revoked_issuer_ids", "predecessor_policy_sha256"))
_R3C_POLICY_FIELDS = _POLICY_FIELDS | frozenset(("vault_admin_verification_keys",))
_R3C_POLICY_FIELDS = _R3C_POLICY_FIELDS | frozenset(("manual_review_permits",))
_KEY_FIELDS = frozenset(("key_id", "identity", "public_key"))
_VAULT_ADMIN_KEY_FIELDS = frozenset(("key_id", "issuer_id", "vault_admin_identity", "public_key", "valid_from", "valid_until"))
_MANUAL_PERMIT_FIELDS = frozenset(("schema", "version", "permit_id", "environment", "git_sha", "evidence_set_id", "signer_role", "evidence_category", "artifact_id", "raw_artifact_sha256", "redacted_artifact_sha256", "valid_from", "valid_until"))
_MANUAL_PERMIT_DOMAIN = b"PROPHET_MANUAL_REVIEW_PERMIT_V1\0"
_ISSUER_FIELDS = frozenset(("issuer_identity", "provider_policy_ids"))
_UNSIGNED_FIELDS = frozenset(("schema", "version", "environment", "git_sha", "trust_policy_id", "trust_policy_version", "trust_policy_sha256", "evidence_set_id", "generated_at", "valid_until", "service_config_fingerprints", "deployment_manifest_fingerprints", "signers", "artifacts", "independence_assertions", "expected_evidence_classifications", "redaction_provenance"))
_PACKAGE_FIELDS = frozenset(("unsigned_package", "signatures", "provider_attestations"))
_SIGNER_FIELDS = frozenset(("signer_role", "signer_id", "signer_public_key", "host", "runtime_principal", "runtime_admin_domain", "service_instance", "vault_auth_principal", "vault_admin_domain", "vault_tenant", "rpc_credential_principal", "rpc_provider", "rpc_account", "journal_storage", "audit_domain", "tls_termination"))
_ARTIFACT_FIELDS = frozenset(("artifact_id", "artifact_sha256", "media_type", "role", "signer_role", "subject_account_scope", "evidence_set_id", "environment", "git_sha", "generated_at", "valid_until", "raw_artifact_sha256", "redacted_artifact_sha256", "redaction_profile_version", "provider_issuer_identity", "provider_attestation_id", "provider_policy_id"))
_SIG_FIELDS = frozenset(("signature_schema", "signature_version", "algorithm", "signer_type", "signer_identity", "issuer_identity", "key_id", "signed_payload_sha256", "signature_bytes", "issued_at", "valid_until"))
_PROVIDER_FIELDS = frozenset(("signature_schema", "signature_version", "algorithm", "signer_type", "signer_identity", "issuer_identity", "provider_attestation_id", "provider_policy_id", "attested_artifact_sha256", "issued_at", "valid_until"))
_RESULT_FIELDS = frozenset(("schema", "version", "provider_attestation_id", "issuer_identity", "subject_account_scope", "environment", "git_sha", "evidence_set_id", "signer_role", "raw_artifact_sha256", "redacted_artifact_sha256", "provider_policy_id", "verified_at", "valid_until", "result"))
_RESULT_V2_FIELDS = _RESULT_FIELDS | frozenset(("issued_at", "evidence_category", "artifact_id", "subject"))
_RESULT_SIGNATURE_FIELDS = frozenset(("signature_schema", "signature_version", "algorithm", "key_id", "signature_bytes"))
_PROVIDER_CATEGORIES = frozenset(("host_vm", "runtime_principal", "runtime_admin_domain", "rpc_credential_principal", "rpc_provider", "rpc_account_project", "journal_storage", "audit_domain", "tls_ingress"))
_PROVIDER_SUBJECT_FIELDS = {
    "host_vm": frozenset(("host_id",)),
    "runtime_principal": frozenset(("runtime_principal_id",)),
    "runtime_admin_domain": frozenset(("runtime_admin_domain_id",)),
    "rpc_credential_principal": frozenset(("rpc_credential_principal_id",)),
    "rpc_provider": frozenset(("rpc_provider_id",)),
    "rpc_account_project": frozenset(("rpc_account_project_id",)),
    "journal_storage": frozenset(("journal_storage_id",)),
    "audit_domain": frozenset(("audit_domain_id",)),
    "tls_ingress": frozenset(("tls_ingress_id",)),
}


def _keys(value: Any, name: str, seen_key_ids: set[str], seen_public_keys: set[bytes]) -> dict[str, tuple[str, str]]:
    if not isinstance(value, list): _fail(f"{name}_invalid")
    result: dict[str, tuple[str, str]] = {}
    for row in value:
        row = _mapping(row, _KEY_FIELDS, name)
        key_id, identity, public_key = _text(row["key_id"], f"{name}_key_id"), _text(row["identity"], f"{name}_identity"), row["public_key"]
        public_key_bytes = _b64url(public_key, f"{name}_public_key", 32)
        if key_id in result or key_id in seen_key_ids: _fail("trust_policy_duplicate_key_id")
        if public_key_bytes in seen_public_keys: _fail("trust_policy_duplicate_public_key")
        result[key_id] = (identity, public_key)
        seen_key_ids.add(key_id)
        seen_public_keys.add(public_key_bytes)
    return result


@dataclass(frozen=True)
class VaultAdminPolicyKey:
    key_id: str
    issuer_id: str
    vault_admin_identity: str
    public_key: str
    valid_from: str
    valid_until: str


@dataclass(frozen=True)
class ParsedR3CTrustPolicy:
    policy_id: str
    policy_version: int
    policy_sha256: str
    deployment_operator_keys: tuple[tuple[str, str, str], ...]
    security_reviewer_keys: tuple[tuple[str, str, str], ...]
    p0c3e2_verification_keys: tuple[tuple[str, str, str], ...]
    vault_admin_verification_keys: tuple[VaultAdminPolicyKey, ...]
    vault_admin_issuers: tuple[str, ...]
    revoked_key_ids: frozenset[str]
    revoked_issuer_ids: frozenset[str]
    manual_review_permits: tuple["ManualReviewPermit", ...]


@dataclass(frozen=True)
class ManualReviewPermit:
    permit_id: str; environment: str; git_sha: str; evidence_set_id: str
    signer_role: str; evidence_category: str; artifact_id: str
    raw_artifact_sha256: str; redacted_artifact_sha256: str; valid_from: str; valid_until: str; provenance_ref: str


@dataclass(frozen=True)
class VerifiedManualReviewPermit:
    """A current-policy fact only; it grants no settlement authority."""
    permit_id: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    environment: str
    git_sha: str
    evidence_set_id: str
    signer_role: str
    evidence_category: str
    artifact_id: str
    raw_artifact_sha256: str
    redacted_artifact_sha256: str
    provenance_ref: str
    valid_from: str
    valid_until: str


def parse_manual_review_permit(value: Any) -> ManualReviewPermit:
    row = _mapping(value, _MANUAL_PERMIT_FIELDS, "manual_review_permit")
    if row["schema"] != "PROPHET_MANUAL_REVIEW_PERMIT_V1" or _integer(row["version"], "manual_review_permit_version") != 1: _fail("manual_review_permit_schema_invalid")
    for name in ("permit_id", "environment", "git_sha", "evidence_set_id", "artifact_id"): _text(row[name], f"manual_review_{name}")
    if row["environment"] != "public-devnet" or row["git_sha"] != BASELINE_GIT_SHA: _fail("manual_review_permit_release_invalid")
    role = parse_signer_role(row["signer_role"]); category = parse_evidence_category(row["evidence_category"])
    if category not in {"journal_storage", "audit_domain"}: _fail("manual_review_permit_category_invalid")
    raw = _hex(row["raw_artifact_sha256"], "manual_review_raw_artifact_sha256"); redacted = _hex(row["redacted_artifact_sha256"], "manual_review_redacted_artifact_sha256")
    start = _timestamp(row["valid_from"], "manual_review_valid_from"); end = _timestamp(row["valid_until"], "manual_review_valid_until")
    if start >= end or end - start > timedelta(hours=72): _fail("manual_review_permit_time_invalid")
    jcs = _jcs(row, "manual_review_permit")
    if len(jcs) > 0xFFFFFFFF: _fail("manual_review_permit_too_large")
    ref = hashlib.sha256(_MANUAL_PERMIT_DOMAIN + struct.pack("<I", len(jcs)) + jcs).hexdigest()
    return ManualReviewPermit(row["permit_id"], row["environment"], row["git_sha"], row["evidence_set_id"], role, category, row["artifact_id"], raw, redacted, row["valid_from"], row["valid_until"], ref)


def verify_manual_review_package_permit(
    item: AuthorizationEvidenceItem,
    *,
    policy: ParsedR3CTrustPolicy,
    verified_evidence: VerifiedOperationalEvidence,
    trusted_now: datetime,
) -> VerifiedManualReviewPermit:
    """Verify one package item against the current parsed policy only.

    This is deliberately capability-free: it neither derives effective
    provenance nor changes settlement or policy state.
    """
    if not isinstance(policy, ParsedR3CTrustPolicy):
        _fail("manual_review_policy_invalid")
    if not isinstance(verified_evidence, VerifiedOperationalEvidence):
        _fail("manual_review_context_invalid")
    if not isinstance(item, AuthorizationEvidenceItem):
        _fail("manual_review_package_item_invalid")
    if not isinstance(trusted_now, datetime) or trusted_now.tzinfo is None or trusted_now.utcoffset() is None:
        _fail("manual_review_trusted_now_invalid")
    now = trusted_now.astimezone(timezone.utc)
    parsed_item = parse_authorization_evidence_item(item.__dict__)
    if parsed_item.provenance_kind != "manual_review_permit":
        _fail("manual_review_provenance_kind_invalid")
    if verified_evidence.schema != EVIDENCE_SCHEMA or verified_evidence.version != 1:
        _fail("manual_review_context_invalid")
    _text(verified_evidence.environment, "manual_review_context_environment")
    _text(verified_evidence.git_sha, "manual_review_context_git_sha")
    _text(verified_evidence.evidence_set_id, "manual_review_context_evidence_set_id")
    _hex(verified_evidence.trust_policy_sha256, "manual_review_context_policy_sha256")
    if verified_evidence.trust_policy_sha256 != policy.policy_sha256:
        _fail("manual_review_policy_context_mismatch")
    matches = tuple(
        permit for permit in policy.manual_review_permits
        if (permit.signer_role, permit.evidence_category, permit.artifact_id,
            permit.raw_artifact_sha256, permit.redacted_artifact_sha256)
        == (parsed_item.signer_role, parsed_item.evidence_category, parsed_item.artifact_id,
            parsed_item.raw_artifact_sha256, parsed_item.redacted_artifact_sha256)
    )
    if len(matches) != 1:
        _fail("manual_review_policy_match_invalid")
    permit = matches[0]
    if parsed_item.provenance_ref != permit.provenance_ref:
        _fail("manual_review_provenance_ref_invalid")
    if (permit.environment, permit.git_sha, permit.evidence_set_id) != (
        verified_evidence.environment, verified_evidence.git_sha, verified_evidence.evidence_set_id,
    ):
        _fail("manual_review_release_context_mismatch")
    valid_from = _timestamp(permit.valid_from, "manual_review_valid_from")
    valid_until = _timestamp(permit.valid_until, "manual_review_valid_until")
    if not valid_from <= now < valid_until:
        _fail("manual_review_permit_not_current")
    return VerifiedManualReviewPermit(
        permit.permit_id, policy.policy_id, policy.policy_version, policy.policy_sha256,
        permit.environment, permit.git_sha, permit.evidence_set_id,
        permit.signer_role, permit.evidence_category, permit.artifact_id,
        permit.raw_artifact_sha256, permit.redacted_artifact_sha256,
        permit.provenance_ref, permit.valid_from, permit.valid_until,
    )


def _r3c_key_family(value: Any, name: str, seen_key_ids: set[str], seen_public_keys: set[bytes], revoked_key_ids: frozenset[str], revoked_issuer_ids: frozenset[str]) -> tuple[tuple[str, str, str], ...]:
    if not isinstance(value, list) or not value:
        _fail(f"r3c_{name}_keys_invalid")
    result: list[tuple[str, str, str]] = []
    for item in value:
        row = _mapping(item, _KEY_FIELDS, f"r3c_{name}_key")
        key_id = _text(row["key_id"], f"r3c_{name}_key_id")
        identity = _text(row["identity"], f"r3c_{name}_identity")
        public_key = row["public_key"]
        decoded = _b64url(public_key, f"r3c_{name}_public_key", 32)
        if key_id in seen_key_ids:
            _fail("r3c_trust_policy_duplicate_key_id")
        if decoded in seen_public_keys:
            _fail("r3c_trust_policy_duplicate_public_key")
        if key_id in revoked_key_ids or identity in revoked_issuer_ids:
            _fail("r3c_trust_policy_revoked_key")
        seen_key_ids.add(key_id)
        seen_public_keys.add(decoded)
        result.append((key_id, identity, public_key))
    return tuple(result)


def _r3c_vault_admin_keys(value: Any, seen_key_ids: set[str], seen_public_keys: set[bytes], issuers: frozenset[str], revoked_key_ids: frozenset[str], revoked_issuer_ids: frozenset[str]) -> tuple[VaultAdminPolicyKey, ...]:
    if not isinstance(value, list) or not value:
        _fail("r3c_vault_admin_keys_invalid")
    result: list[VaultAdminPolicyKey] = []
    for item in value:
        row = _mapping(item, _VAULT_ADMIN_KEY_FIELDS, "r3c_vault_admin_key")
        key_id = _text(row["key_id"], "r3c_vault_admin_key_id")
        issuer_id = _text(row["issuer_id"], "r3c_vault_admin_issuer_id")
        identity = _text(row["vault_admin_identity"], "r3c_vault_admin_identity")
        public_key = row["public_key"]
        decoded = _b64url(public_key, "r3c_vault_admin_public_key", 32)
        valid_from = _timestamp(row["valid_from"], "r3c_vault_admin_valid_from")
        valid_until = _timestamp(row["valid_until"], "r3c_vault_admin_valid_until")
        if valid_from >= valid_until:
            _fail("r3c_vault_admin_key_time_invalid")
        if key_id in seen_key_ids:
            _fail("r3c_trust_policy_duplicate_key_id")
        if decoded in seen_public_keys:
            _fail("r3c_trust_policy_duplicate_public_key")
        if key_id in revoked_key_ids or issuer_id in revoked_issuer_ids:
            _fail("r3c_trust_policy_revoked_key")
        if issuer_id not in issuers:
            _fail("r3c_vault_admin_issuer_untrusted")
        seen_key_ids.add(key_id)
        seen_public_keys.add(decoded)
        result.append(VaultAdminPolicyKey(key_id, issuer_id, identity, public_key, row["valid_from"], row["valid_until"]))
    return tuple(result)


def parse_r3c_trust_policy(value: Any) -> ParsedR3CTrustPolicy:
    """Strict non-authorizing R3C policy parser; I4 owns policy activation."""
    row = _mapping(value, _R3C_POLICY_FIELDS, "r3c_trust_policy")
    if row["schema"] != R3C_POLICY_SCHEMA or _integer(row["version"], "r3c_trust_policy_version") != 2:
        _fail("r3c_trust_policy_schema_invalid")
    policy_id = _text(row["policy_id"], "r3c_policy_id")
    policy_version = _integer(row["policy_version"], "r3c_policy_version")
    if row["environment"] != "public-devnet":
        _fail("r3c_trust_policy_environment_invalid")
    if not isinstance(row["release_scope"], list) or row["release_scope"] != [BASELINE_GIT_SHA]:
        _fail("r3c_trust_policy_release_scope_invalid")
    if not isinstance(row["allowed_algorithms"], list) or set(row["allowed_algorithms"]) != {"ed25519", "provider-native-v1"}:
        _fail("r3c_trust_policy_algorithms_invalid")
    if not isinstance(row["revoked_key_ids"], list) or not isinstance(row["revoked_issuer_ids"], list):
        _fail("r3c_trust_policy_revocation_invalid")
    revoked_keys = frozenset(_text(item, "r3c_revoked_key_id") for item in row["revoked_key_ids"])
    revoked_issuers = frozenset(_text(item, "r3c_revoked_issuer_id") for item in row["revoked_issuer_ids"])
    if len(revoked_keys) != len(row["revoked_key_ids"]) or len(revoked_issuers) != len(row["revoked_issuer_ids"]):
        _fail("r3c_trust_policy_revocation_invalid")
    if row["predecessor_policy_sha256"] is not None:
        _hex(row["predecessor_policy_sha256"], "r3c_predecessor_policy_sha256")
    if not isinstance(row["vault_admin_issuers"], list) or not row["vault_admin_issuers"]:
        _fail("r3c_vault_admin_issuers_invalid")
    issuers = frozenset(_text(item, "r3c_vault_admin_issuer") for item in row["vault_admin_issuers"])
    if len(issuers) != len(row["vault_admin_issuers"]):
        _fail("r3c_vault_admin_issuers_invalid")
    if not isinstance(row["provider_issuer_policies"], list):
        _fail("r3c_provider_issuer_policies_invalid")
    # Preserve the existing policy parser's strict provider-policy shape even
    # though provider-result v2 activation belongs exclusively to I2.
    provider_ids: set[str] = set()
    for item in row["provider_issuer_policies"]:
        item = _mapping(item, _ISSUER_FIELDS, "r3c_provider_issuer_policy")
        issuer = _text(item["issuer_identity"], "r3c_provider_issuer_identity")
        policies = item["provider_policy_ids"]
        if issuer in provider_ids or not isinstance(policies, list) or not policies:
            _fail("r3c_provider_issuer_policies_invalid")
        provider_ids.add(issuer)
        if len({_text(policy, "r3c_provider_policy_id") for policy in policies}) != len(policies):
            _fail("r3c_provider_issuer_policies_invalid")
    if not isinstance(row["manual_review_permits"], list): _fail("manual_review_permits_invalid")
    permits = tuple(parse_manual_review_permit(item) for item in row["manual_review_permits"])
    if len({permit.permit_id for permit in permits}) != len(permits): _fail("manual_review_permit_duplicate_id")
    targets = {(p.signer_role, p.evidence_category, p.artifact_id, p.raw_artifact_sha256, p.redacted_artifact_sha256) for p in permits}
    if len(targets) != len(permits): _fail("manual_review_permit_duplicate_target")
    seen_key_ids: set[str] = set()
    seen_public_keys: set[bytes] = set()
    operators = _r3c_key_family(row["deployment_operator_keys"], "deployment_operator", seen_key_ids, seen_public_keys, revoked_keys, revoked_issuers)
    reviewers = _r3c_key_family(row["security_reviewer_keys"], "security_reviewer", seen_key_ids, seen_public_keys, revoked_keys, revoked_issuers)
    p0c3e2 = _r3c_key_family(row["p0c3e2_verification_keys"], "p0c3e2", seen_key_ids, seen_public_keys, revoked_keys, revoked_issuers)
    vault = _r3c_vault_admin_keys(row["vault_admin_verification_keys"], seen_key_ids, seen_public_keys, issuers, revoked_keys, revoked_issuers)
    if {identity for _, identity, _ in operators}.intersection(identity for _, identity, _ in reviewers):
        _fail("r3c_trust_policy_reviewer_identity_collision")
    digest = hashlib.sha256(_jcs(row, "r3c_trust_policy")).hexdigest()
    return ParsedR3CTrustPolicy(policy_id, policy_version, digest, operators, reviewers, p0c3e2, vault, tuple(sorted(issuers)), revoked_keys, revoked_issuers, permits)


def _validate_policy(policy: Any) -> tuple[Mapping[str, Any], str, dict[str, tuple[str, str]], dict[str, tuple[str, str]], dict[str, tuple[str, str]], dict[str, frozenset[str]]]:
    row = _mapping(policy, _POLICY_FIELDS, "trust_policy")
    if row["schema"] != POLICY_SCHEMA or _integer(row["version"], "trust_policy_version") != 1: _fail("trust_policy_schema_unsupported")
    _text(row["policy_id"], "policy_id"); _integer(row["policy_version"], "policy_version")
    if row["environment"] != "public-devnet": _fail("trust_policy_environment_invalid")
    if not isinstance(row["release_scope"], list) or row["release_scope"] != [BASELINE_GIT_SHA]: _fail("trust_policy_release_scope_invalid")
    if not isinstance(row["allowed_algorithms"], list) or set(row["allowed_algorithms"]) != {"ed25519", "provider-native-v1"}: _fail("trust_policy_algorithms_invalid")
    seen_key_ids: set[str] = set()
    seen_public_keys: set[bytes] = set()
    operators = _keys(row["deployment_operator_keys"], "operator_keys", seen_key_ids, seen_public_keys)
    reviewers = _keys(row["security_reviewer_keys"], "reviewer_keys", seen_key_ids, seen_public_keys)
    p0c3e2 = _keys(row["p0c3e2_verification_keys"], "p0c3e2_keys", seen_key_ids, seen_public_keys)
    if not operators or not reviewers or not p0c3e2: _fail("trust_policy_keys_missing")
    if set(identity for identity, _ in operators.values()).intersection(identity for identity, _ in reviewers.values()): _fail("trust_policy_reviewer_identity_collision")
    if not isinstance(row["vault_admin_issuers"], list) or not isinstance(row["provider_issuer_policies"], list): _fail("trust_policy_issuers_invalid")
    for issuer in row["vault_admin_issuers"]: _text(issuer, "vault_admin_issuer")
    provider_ids: set[str] = set()
    provider_policies: dict[str, frozenset[str]] = {}
    for item in row["provider_issuer_policies"]:
        item = _mapping(item, _ISSUER_FIELDS, "provider_issuer_policy")
        identity = _text(item["issuer_identity"], "provider_issuer_identity")
        if identity in provider_ids or not isinstance(item["provider_policy_ids"], list): _fail("provider_issuer_policy_invalid")
        provider_ids.add(identity)
        policies = frozenset(_text(policy_id, "provider_policy_id") for policy_id in item["provider_policy_ids"])
        if not policies: _fail("provider_issuer_policy_invalid")
        provider_policies[identity] = policies
    if not isinstance(row["revoked_key_ids"], list) or not isinstance(row["revoked_issuer_ids"], list): _fail("trust_policy_revocation_invalid")
    for value in row["revoked_key_ids"] + row["revoked_issuer_ids"]: _text(value, "revocation_id")
    if row["predecessor_policy_sha256"] is not None: _hex(row["predecessor_policy_sha256"], "predecessor_policy_sha256")
    return row, hashlib.sha256(_jcs(row, "trust_policy")).hexdigest(), operators, reviewers, p0c3e2, provider_policies


def _validate_unsigned(value: Any) -> Mapping[str, Any]:
    row = _mapping(value, _UNSIGNED_FIELDS, "unsigned_package")
    if row["schema"] != EVIDENCE_SCHEMA or _integer(row["version"], "evidence_version") != 1: _fail("evidence_schema_unsupported")
    if row["environment"] != "public-devnet" or row["git_sha"] != BASELINE_GIT_SHA: _fail("evidence_release_invalid")
    for field in ("trust_policy_id", "evidence_set_id"): _text(row[field], field)
    _integer(row["trust_policy_version"], "evidence_policy_version"); _hex(row["trust_policy_sha256"], "trust_policy_sha256")
    _timestamp(row["generated_at"], "generated_at"); _timestamp(row["valid_until"], "valid_until")
    for name, expected in (("service_config_fingerprints", {"A", "B"}), ("deployment_manifest_fingerprints", {"A", "B"})):
        item = _mapping(row[name], frozenset(expected), name)
        for digest in item.values(): _hex(digest, name)
    if not isinstance(row["signers"], list) or len(row["signers"]) != 2: _fail("signers_invalid")
    roles: set[str] = set()
    for signer in row["signers"]:
        signer = _mapping(signer, _SIGNER_FIELDS, "signer")
        role = signer["signer_role"]
        if role not in ("A", "B") or role in roles: _fail("signer_role_invalid")
        roles.add(role)
        for field in _SIGNER_FIELDS - {"signer_role", "signer_public_key"}: _text(signer[field], f"signer_{field}")
        try:
            if str(Pubkey.from_string(signer["signer_public_key"])) != signer["signer_public_key"]: raise ValueError
        except Exception as exc: raise OperationalEvidenceError("signer_public_key_invalid") from exc
    if roles != {"A", "B"} or not isinstance(row["artifacts"], list) or len(row["artifacts"]) != 2: _fail("signers_invalid")
    artifact_roles: set[str] = set()
    artifact_ids: set[str] = set()
    provider_attestation_ids: set[str] = set()
    signer_specific_hashes: set[tuple[str, str, str]] = set()
    for artifact in row["artifacts"]:
        artifact = _mapping(artifact, _ARTIFACT_FIELDS, "artifact")
        for field in ("artifact_id", "media_type", "role", "signer_role", "subject_account_scope", "evidence_set_id", "environment", "git_sha", "redaction_profile_version", "provider_issuer_identity", "provider_attestation_id", "provider_policy_id"): _text(artifact[field], f"artifact_{field}")
        for field in ("artifact_sha256", "raw_artifact_sha256", "redacted_artifact_sha256"): _hex(artifact[field], f"artifact_{field}")
        if (artifact["role"] != "infrastructure" or artifact["signer_role"] not in ("A", "B")
                or artifact["signer_role"] in artifact_roles
                or artifact["artifact_id"] in artifact_ids
                or artifact["provider_attestation_id"] in provider_attestation_ids
                or (artifact["artifact_sha256"], artifact["raw_artifact_sha256"], artifact["redacted_artifact_sha256"]) in signer_specific_hashes
                or artifact["evidence_set_id"] != row["evidence_set_id"]
                or artifact["environment"] != row["environment"]
                or artifact["git_sha"] != row["git_sha"]): _fail("artifact_binding_invalid")
        artifact_roles.add(artifact["signer_role"])
        artifact_ids.add(artifact["artifact_id"])
        provider_attestation_ids.add(artifact["provider_attestation_id"])
        signer_specific_hashes.add((artifact["artifact_sha256"], artifact["raw_artifact_sha256"], artifact["redacted_artifact_sha256"]))
        _timestamp(artifact["generated_at"], "artifact_generated_at"); _timestamp(artifact["valid_until"], "artifact_valid_until")
    if artifact_roles != {"A", "B"}: _fail("artifact_role_coverage_invalid")
    if not isinstance(row["independence_assertions"], dict) or not isinstance(row["expected_evidence_classifications"], dict) or not isinstance(row["redaction_provenance"], dict): _fail("evidence_claims_invalid")
    return row


def _validate_result(value: Any) -> Mapping[str, Any]:
    row = _mapping(value, _RESULT_FIELDS, "provider_result")
    if row["schema"] != RESULT_SCHEMA or _integer(row["version"], "provider_result_version") != 1 or row["result"] != "VERIFIED": _fail("provider_result_schema_unsupported")
    for field in ("provider_attestation_id", "issuer_identity", "subject_account_scope", "environment", "git_sha", "evidence_set_id", "signer_role", "provider_policy_id"): _text(row[field], field)
    if row["environment"] != "public-devnet" or row["git_sha"] != BASELINE_GIT_SHA or row["signer_role"] not in ("A", "B"): _fail("provider_result_binding_invalid")
    for field in ("raw_artifact_sha256", "redacted_artifact_sha256"): _hex(row[field], field)
    _timestamp(row["verified_at"], "verified_at"); _timestamp(row["valid_until"], "result_valid_until")
    return row


def _signature(value: Any, unsigned: Mapping[str, Any], generated: datetime, package_until: datetime, keys: Mapping[str, tuple[str, str]], revoked_key_ids: Sequence[str], role: str) -> tuple[str, str, str]:
    row = _mapping(value, _SIG_FIELDS, "evidence_signature")
    if row["signature_schema"] != EVIDENCE_SIGNATURE_SCHEMA or _integer(row["signature_version"], "signature_version") != 1 or row["algorithm"] != "ed25519" or row["signer_type"] != role: _fail("evidence_signature_schema_invalid")
    identity, issuer, key_id = _text(row["signer_identity"], "signature_identity"), _text(row["issuer_identity"], "signature_issuer"), _text(row["key_id"], "signature_key_id")
    if key_id not in keys or keys[key_id][0] != identity or issuer != identity: _fail("evidence_signature_key_untrusted")
    if key_id in revoked_key_ids: _fail("evidence_signature_key_revoked")
    digest = _hex(row["signed_payload_sha256"], "signed_payload_sha256")
    preimage = evidence_preimage(unsigned)
    if digest != hashlib.sha256(preimage).hexdigest(): _fail("evidence_signature_digest_invalid")
    issued, until = _timestamp(row["issued_at"], "signature_issued_at"), _timestamp(row["valid_until"], "signature_valid_until")
    if issued < generated - timedelta(minutes=5) or issued > package_until or until != package_until: _fail("evidence_signature_time_invalid")
    _verify_ed25519(keys[key_id][1], row["signature_bytes"], preimage, "evidence")
    return identity, key_id, keys[key_id][1]


def _check_freshness(unsigned: Mapping[str, Any], now: datetime) -> tuple[datetime, datetime]:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0): _fail("trusted_time_invalid")
    generated, until = _timestamp(unsigned["generated_at"], "generated_at"), _timestamp(unsigned["valid_until"], "valid_until")
    if generated > now + timedelta(minutes=5) or now - generated > timedelta(hours=24) or until <= now or until <= generated or until - generated > timedelta(hours=72): _fail("evidence_freshness_invalid")
    return generated, until


def _provider_record(value: Any) -> Mapping[str, Any]:
    row = _mapping(value, _PROVIDER_FIELDS, "provider_attestation")
    if row["signature_schema"] != PROVIDER_ATTESTATION_SCHEMA or _integer(row["signature_version"], "provider_signature_version") != 1 or row["algorithm"] != "provider-native-v1" or row["signer_type"] != "provider": _fail("provider_attestation_schema_invalid")
    for field in ("signer_identity", "issuer_identity", "provider_attestation_id", "provider_policy_id"): _text(row[field], field)
    _hex(row["attested_artifact_sha256"], "attested_artifact_sha256")
    _timestamp(row["issued_at"], "provider_issued_at"); _timestamp(row["valid_until"], "provider_valid_until")
    return row


def _provider_result(value: Any, policy_keys: Mapping[str, tuple[str, str]], revoked_key_ids: Sequence[str], now: datetime, package_until: datetime) -> Mapping[str, Any]:
    row = _mapping(value, frozenset(("unsigned_result", "signature")), "signed_provider_result")
    unsigned = _validate_result(row["unsigned_result"])
    sig = _mapping(row["signature"], _RESULT_SIGNATURE_FIELDS, "provider_result_signature")
    if sig["signature_schema"] != RESULT_SIGNATURE_SCHEMA or _integer(sig["signature_version"], "result_signature_version") != 1 or sig["algorithm"] != "ed25519": _fail("provider_result_signature_schema_invalid")
    key_id = _text(sig["key_id"], "provider_result_key_id")
    if key_id not in policy_keys: _fail("provider_result_key_untrusted")
    if key_id in revoked_key_ids: _fail("provider_result_key_revoked")
    verified, until = _timestamp(unsigned["verified_at"], "verified_at"), _timestamp(unsigned["valid_until"], "result_valid_until")
    if (verified >= until
            or verified > now + timedelta(minutes=5)
            or now - verified > timedelta(hours=24)
            or until - verified > timedelta(hours=72)
            or until <= now
            or until > package_until): _fail("provider_result_time_invalid")
    _verify_ed25519(policy_keys[key_id][1], sig["signature_bytes"], result_preimage(unsigned), "provider_result")
    return unsigned


def _bind_static(unsigned: Mapping[str, Any], bindings: Sequence[StaticSignerBinding]) -> None:
    if not isinstance(bindings, Sequence) or len(bindings) != 2: _fail("static_bindings_invalid")
    expected = {binding.signer_role: binding for binding in bindings if isinstance(binding, StaticSignerBinding)}
    if set(expected) != {"A", "B"}: _fail("static_bindings_invalid")
    actual = {signer["signer_role"]: signer for signer in unsigned["signers"]}
    for role, binding in expected.items():
        signer = actual[role]
        if (unsigned["service_config_fingerprints"][role] != binding.service_config_fingerprint or unsigned["deployment_manifest_fingerprints"][role] != binding.deployment_manifest_fingerprint or signer["signer_id"] != binding.signer_id or signer["signer_public_key"] != binding.signer_public_key): _fail("static_binding_mismatch")


def _derive(unsigned: Mapping[str, Any]) -> tuple[tuple[tuple[str, bool], ...], dict[str, str]]:
    a, b = sorted(unsigned["signers"], key=lambda x: x["signer_role"])
    fields = ("signer_public_key", "host", "runtime_principal", "runtime_admin_domain", "service_instance", "vault_auth_principal", "vault_admin_domain", "vault_tenant", "rpc_credential_principal", "rpc_provider", "rpc_account", "journal_storage", "audit_domain", "tls_termination")
    assertions = tuple((field, a[field] != b[field]) for field in fields)
    if not all(value for _, value in assertions): _fail("independence_collision")
    claim = unsigned["independence_assertions"]
    if set(claim) != {name for name, _ in assertions} or any(type(claim[name]) is not bool or claim[name] != value for name, value in assertions): _fail("independence_claim_mismatch")
    effective = {"host": "PROVIDER_ATTESTED", "runtime": "PROVIDER_ATTESTED", "vault": "VAULT_ADMIN_ATTESTED", "vault_key": "VAULT_ADMIN_ATTESTED", "rpc": "PROVIDER_ATTESTED", "journal": "PROVIDER_ATTESTED", "audit": "PROVIDER_ATTESTED", "tls": "PROVIDER_ATTESTED", "process": "MACHINE_VERIFIED"}
    claims = unsigned["expected_evidence_classifications"]
    if set(claims) != _REQUIRED_CATEGORIES or any(claims[key] != value for key, value in effective.items()): _fail("classification_claim_mismatch")
    return assertions, effective


def _verify_legacy_operational_evidence_for_i5_vectors(package: Mapping[str, Any], *, authoritative_policy: Mapping[str, Any], authorized_policy_digests: Mapping[tuple[str, int], str], static_bindings: Sequence[StaticSignerBinding], normalized_provider_results: Sequence[Mapping[str, Any]], now: datetime) -> VerifiedOperationalEvidence:
    """Historical global-vector compatibility only; never an authority path."""
    policy, policy_digest, operators, reviewers, result_keys, provider_policies = _validate_policy(authoritative_policy)
    if authorized_policy_digests.get((policy["policy_id"], policy["policy_version"])) != policy_digest: _fail("trust_policy_not_authorized")
    row = _mapping(package, _PACKAGE_FIELDS, "evidence_package")
    unsigned = _validate_unsigned(row["unsigned_package"])
    if (unsigned["trust_policy_id"], unsigned["trust_policy_version"], unsigned["trust_policy_sha256"]) != (policy["policy_id"], policy["policy_version"], policy_digest): _fail("trust_policy_binding_mismatch")
    generated, package_until = _check_freshness(unsigned, now)
    if not isinstance(row["signatures"], list) or len(row["signatures"]) != 2: _fail("reviewer_quorum_invalid")
    accepted: dict[str, tuple[str, str, str]] = {}
    for signature in row["signatures"]:
        if not isinstance(signature, dict): _fail("reviewer_quorum_invalid")
        role = signature.get("signer_type")
        if role == "deployment-operator": keys = operators
        elif role == "security-reviewer": keys = reviewers
        else: _fail("reviewer_role_invalid")
        if role in accepted: _fail("reviewer_role_duplicate")
        accepted[role] = _signature(signature, unsigned, generated, package_until, keys, policy["revoked_key_ids"], role)
    if set(accepted) != {"deployment-operator", "security-reviewer"}: _fail("reviewer_quorum_invalid")
    if len({item[0] for item in accepted.values()}) != 2 or len({item[1] for item in accepted.values()}) != 2 or len({item[2] for item in accepted.values()}) != 2: _fail("reviewer_identity_collision")
    _bind_static(unsigned, static_bindings)
    if any(item[1] in policy["revoked_key_ids"] or item[0] in policy["revoked_issuer_ids"] for item in accepted.values()): _fail("reviewer_revoked")
    providers = [_provider_record(item) for item in row["provider_attestations"]] if isinstance(row["provider_attestations"], list) else (_fail("provider_attestations_invalid"))
    results = [_provider_result(item, result_keys, policy["revoked_key_ids"], now, package_until) for item in normalized_provider_results]
    if len(providers) != len(results) or len(providers) != len(unsigned["artifacts"]): _fail("provider_result_count_invalid")
    if (len({provider["provider_attestation_id"] for provider in providers}) != len(providers)
            or len({result["provider_attestation_id"] for result in results}) != len(results)
            or {result["signer_role"] for result in results} != {"A", "B"}): _fail("provider_result_role_coverage_invalid")
    for artifact, provider, result in zip(unsigned["artifacts"], providers, results):
        if provider["issuer_identity"] in policy["revoked_issuer_ids"] or provider["issuer_identity"] not in provider_policies or provider["provider_policy_id"] not in provider_policies[provider["issuer_identity"]]: _fail("provider_issuer_untrusted")
        if (provider["provider_attestation_id"], provider["issuer_identity"], provider["provider_policy_id"], provider["attested_artifact_sha256"]) != (artifact["provider_attestation_id"], artifact["provider_issuer_identity"], artifact["provider_policy_id"], artifact["raw_artifact_sha256"]): _fail("provider_artifact_binding_invalid")
        wanted = (artifact["provider_attestation_id"], artifact["provider_issuer_identity"], artifact["subject_account_scope"], artifact["signer_role"], artifact["raw_artifact_sha256"], artifact["redacted_artifact_sha256"], artifact["provider_policy_id"], unsigned["evidence_set_id"], unsigned["environment"], unsigned["git_sha"])
        actual = (result["provider_attestation_id"], result["issuer_identity"], result["subject_account_scope"], result["signer_role"], result["raw_artifact_sha256"], result["redacted_artifact_sha256"], result["provider_policy_id"], result["evidence_set_id"], result["environment"], result["git_sha"])
        if actual != wanted: _fail("provider_result_binding_invalid")
    assertions, classifications = _derive(unsigned)
    preimage = evidence_preimage(unsigned)
    return VerifiedOperationalEvidence(EVIDENCE_SCHEMA, 1, unsigned["evidence_set_id"], unsigned["environment"], unsigned["git_sha"], policy_digest, hashlib.sha256(preimage).hexdigest(), accepted["deployment-operator"][0], accepted["deployment-operator"][1], accepted["security-reviewer"][0], accepted["security-reviewer"][1], unsigned["service_config_fingerprints"]["A"], unsigned["service_config_fingerprints"]["B"], unsigned["deployment_manifest_fingerprints"]["A"], unsigned["deployment_manifest_fingerprints"]["B"], assertions, tuple(sorted(classifications.items())), unsigned["generated_at"], unsigned["valid_until"])
