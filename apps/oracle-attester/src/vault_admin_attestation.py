"""Pure verification for category-bound Vault-admin attestations.

This module deliberately has no Vault, network, environment, or package-level
authorization capability.  P0C3E1 integration must explicitly consume its
immutable result in a later change.
"""
from __future__ import annotations

import base64
import hashlib
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

import rfc8785
from solders.pubkey import Pubkey
from solders.signature import Signature


ATTESTATION_SCHEMA = "PROPHET_VAULT_ADMIN_ATTESTATION_V1"
SIGNATURE_SCHEMA = "PROPHET_VAULT_ADMIN_ATTESTATION_SIGNATURE_V1"
DOMAIN = b"PROPHET_VAULT_ADMIN_ATTESTATION_V1\0"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_CATEGORIES = frozenset(("vault_auth_principal", "vault_admin_domain", "vault_account_tenant", "vault_key_identity_version"))
_UNSIGNED = frozenset(("schema", "version", "environment", "git_sha", "evidence_set_id", "signer_role", "evidence_category", "artifact_id", "raw_artifact_sha256", "redacted_artifact_sha256", "issuer_id", "vault_admin_identity", "key_id", "subject", "issued_at", "valid_until"))
_SIGNATURE = frozenset(("schema", "version", "algorithm", "signer_type", "issuer_id", "vault_admin_identity", "key_id", "signed_payload_sha256", "signature", "issued_at", "valid_until"))
_KEY = frozenset(("key_id", "issuer_id", "vault_admin_identity", "public_key", "valid_from", "valid_until"))


class VaultAdminAttestationError(ValueError):
    pass


def _fail(code: str) -> None:
    raise VaultAdminAttestationError(code)


def _map(value: Any, fields: frozenset[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(f"{name}_shape_invalid")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or not _ID.fullmatch(value):
        _fail(f"{name}_invalid")
    return value


def _hex(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        _fail(f"{name}_invalid")
    return value


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail(f"{name}_invalid")
    return value


def _time(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        _fail(f"{name}_invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise VaultAdminAttestationError(f"{name}_invalid") from exc


def _b64(value: Any, name: str, size: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        _fail(f"{name}_invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise VaultAdminAttestationError(f"{name}_invalid") from exc
    if len(raw) != size or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        _fail(f"{name}_invalid")
    return raw


@dataclass(frozen=True)
class TrustedVaultSubject:
    vault_auth_principal_id: str
    vault_admin_domain_id: str
    vault_account_or_tenant_id: str
    vault_key_name: str
    signer_key_version: int
    signer_public_key: str

    def __post_init__(self) -> None:
        for name, value in (("vault_auth_principal_id", self.vault_auth_principal_id), ("vault_admin_domain_id", self.vault_admin_domain_id), ("vault_account_or_tenant_id", self.vault_account_or_tenant_id), ("vault_key_name", self.vault_key_name)):
            _text(value, name)
        _integer(self.signer_key_version, "signer_key_version")
        try:
            if str(Pubkey.from_string(self.signer_public_key)) != self.signer_public_key:
                raise ValueError
        except Exception as exc:
            raise VaultAdminAttestationError("signer_public_key_invalid") from exc


@dataclass(frozen=True)
class VaultAdminVerificationKey:
    key_id: str
    issuer_id: str
    vault_admin_identity: str
    public_key: str
    valid_from: str
    valid_until: str

    @classmethod
    def from_mapping(cls, value: Any) -> "VaultAdminVerificationKey":
        row = _map(value, _KEY, "vault_admin_key")
        return cls(*(_text(row[x], f"vault_admin_key_{x}") if x not in ("public_key", "valid_from", "valid_until") else row[x] for x in ("key_id", "issuer_id", "vault_admin_identity", "public_key", "valid_from", "valid_until")))

    def __post_init__(self) -> None:
        _text(self.key_id, "vault_admin_key_id"); _text(self.issuer_id, "vault_admin_issuer_id"); _text(self.vault_admin_identity, "vault_admin_identity")
        _b64(self.public_key, "vault_admin_public_key", 32)
        if _time(self.valid_from, "vault_admin_key_valid_from") >= _time(self.valid_until, "vault_admin_key_valid_until"):
            _fail("vault_admin_key_time_invalid")


@dataclass(frozen=True)
class AuthoritativeEd25519Key:
    key_id: str
    public_key: str

    def __post_init__(self) -> None:
        _text(self.key_id, "authoritative_key_id")
        _b64(self.public_key, "authoritative_public_key", 32)


@dataclass(frozen=True)
class VerifiedVaultAdminAttestation:
    issuer_id: str
    vault_admin_identity: str
    key_id: str
    signer_role: str
    evidence_category: str
    artifact_id: str
    subject: tuple[tuple[str, str | int], ...]
    preimage_sha256: str
    issued_at: str
    valid_until: str


def attestation_preimage(unsigned: Mapping[str, Any]) -> bytes:
    _validate_unsigned(unsigned)
    try:
        encoded = rfc8785.dumps(unsigned)
    except Exception as exc:
        raise VaultAdminAttestationError("vault_admin_canonicalization_failed") from exc
    if len(encoded) > 0xFFFFFFFF:
        _fail("vault_admin_attestation_too_large")
    return DOMAIN + struct.pack("<I", len(encoded)) + encoded


def _subject(category: str, value: Any) -> Mapping[str, Any]:
    fields = {
        "vault_auth_principal": frozenset(("vault_auth_principal_id",)),
        "vault_admin_domain": frozenset(("vault_admin_domain_id",)),
        "vault_account_tenant": frozenset(("vault_account_or_tenant_id",)),
        "vault_key_identity_version": frozenset(("vault_key_name", "signer_key_version", "signer_public_key")),
    }[category]
    row = _map(value, fields, "vault_admin_subject")
    for name, item in row.items():
        if name == "signer_key_version": _integer(item, name)
        elif name == "signer_public_key":
            try:
                if str(Pubkey.from_string(item)) != item:
                    raise ValueError
            except Exception as exc:
                raise VaultAdminAttestationError(f"{name}_invalid") from exc
        else: _text(item, name)
    return row


def _validate_unsigned(value: Any) -> Mapping[str, Any]:
    row = _map(value, _UNSIGNED, "vault_admin_attestation")
    if row["schema"] != ATTESTATION_SCHEMA or _integer(row["version"], "vault_admin_attestation_version") != 1:
        _fail("vault_admin_attestation_schema_invalid")
    for name in ("environment", "git_sha", "evidence_set_id", "artifact_id", "issuer_id", "vault_admin_identity", "key_id"):
        _text(row[name], name)
    _hex(row["raw_artifact_sha256"], "raw_artifact_sha256"); _hex(row["redacted_artifact_sha256"], "redacted_artifact_sha256")
    if row["signer_role"] not in ("A", "B") or row["evidence_category"] not in _CATEGORIES:
        _fail("vault_admin_attestation_context_invalid")
    _subject(row["evidence_category"], row["subject"])
    _time(row["issued_at"], "vault_admin_issued_at"); _time(row["valid_until"], "vault_admin_valid_until")
    return row


def validate_vault_admin_key_set(keys: Sequence[VaultAdminVerificationKey], *, deployment_operator_keys: Sequence[AuthoritativeEd25519Key], security_reviewer_keys: Sequence[AuthoritativeEd25519Key], p0c3e2_verification_keys: Sequence[AuthoritativeEd25519Key]) -> dict[str, VaultAdminVerificationKey]:
    result: dict[str, VaultAdminVerificationKey] = {}
    for role, trust_keys in (("deployment_operator", deployment_operator_keys), ("security_reviewer", security_reviewer_keys), ("p0c3e2", p0c3e2_verification_keys)):
        if not isinstance(trust_keys, Sequence) or not trust_keys:
            _fail(f"vault_admin_missing_{role}_keys")
        for trust_key in trust_keys:
            if not isinstance(trust_key, AuthoritativeEd25519Key): _fail(f"vault_admin_{role}_keys_invalid")
            _b64(trust_key.public_key, f"vault_admin_{role}_public_key", 32)
    seen: set[bytes] = set()
    for key in keys:
        if not isinstance(key, VaultAdminVerificationKey) or key.key_id in result:
            _fail("vault_admin_duplicate_key_id")
        raw = _b64(key.public_key, "vault_admin_public_key", 32)
        for trust_keys in (deployment_operator_keys, security_reviewer_keys, p0c3e2_verification_keys):
            if any(raw == _b64(item.public_key, "authoritative_public_key", 32) for item in trust_keys):
                _fail("vault_admin_duplicate_public_key")
        if raw in seen: _fail("vault_admin_duplicate_public_key")
        seen.add(raw); result[key.key_id] = key
    return result


def verify_vault_admin_attestation(value: Any, *, keys: Sequence[VaultAdminVerificationKey], deployment_operator_keys: Sequence[AuthoritativeEd25519Key], security_reviewer_keys: Sequence[AuthoritativeEd25519Key], p0c3e2_verification_keys: Sequence[AuthoritativeEd25519Key], vault_admin_issuers: Sequence[str], revoked_key_ids: Sequence[str], revoked_issuer_ids: Sequence[str], trusted_subject: TrustedVaultSubject, expected_environment: str, expected_git_sha: str, expected_evidence_set_id: str, expected_signer_role: str, expected_evidence_category: str, expected_artifact_id: str, expected_raw_artifact_sha256: str, expected_redacted_artifact_sha256: str, package_valid_until: str, now: datetime) -> VerifiedVaultAdminAttestation:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0): _fail("trusted_time_invalid")
    row = _map(value, frozenset(("unsigned_attestation", "signature")), "signed_vault_admin_attestation")
    unsigned = _validate_unsigned(row["unsigned_attestation"])
    expected = (expected_environment, expected_git_sha, expected_evidence_set_id, expected_signer_role, expected_evidence_category, expected_artifact_id, expected_raw_artifact_sha256, expected_redacted_artifact_sha256)
    actual = (unsigned["environment"], unsigned["git_sha"], unsigned["evidence_set_id"], unsigned["signer_role"], unsigned["evidence_category"], unsigned["artifact_id"], unsigned["raw_artifact_sha256"], unsigned["redacted_artifact_sha256"])
    if actual != expected: _fail("vault_admin_context_binding_invalid")
    subject = _subject(unsigned["evidence_category"], unsigned["subject"])
    trusted = {"vault_auth_principal": {"vault_auth_principal_id": trusted_subject.vault_auth_principal_id}, "vault_admin_domain": {"vault_admin_domain_id": trusted_subject.vault_admin_domain_id}, "vault_account_tenant": {"vault_account_or_tenant_id": trusted_subject.vault_account_or_tenant_id}, "vault_key_identity_version": {"vault_key_name": trusted_subject.vault_key_name, "signer_key_version": trusted_subject.signer_key_version, "signer_public_key": trusted_subject.signer_public_key}}[unsigned["evidence_category"]]
    if dict(subject) != trusted: _fail("vault_admin_subject_binding_invalid")
    key = validate_vault_admin_key_set(keys, deployment_operator_keys=deployment_operator_keys, security_reviewer_keys=security_reviewer_keys, p0c3e2_verification_keys=p0c3e2_verification_keys).get(unsigned["key_id"])
    if key is None or unsigned["key_id"] in revoked_key_ids or unsigned["issuer_id"] in revoked_issuer_ids: _fail("vault_admin_key_untrusted")
    if unsigned["issuer_id"] not in vault_admin_issuers or (key.issuer_id, key.vault_admin_identity) != (unsigned["issuer_id"], unsigned["vault_admin_identity"]): _fail("vault_admin_issuer_untrusted")
    issued, until, package_until = _time(unsigned["issued_at"], "vault_admin_issued_at"), _time(unsigned["valid_until"], "vault_admin_valid_until"), _time(package_valid_until, "package_valid_until")
    key_until = _time(key.valid_until, "vault_admin_key_valid_until")
    if issued >= until or issued > now + timedelta(minutes=5) or now - issued > timedelta(hours=24) or until <= now or until - issued > timedelta(hours=72) or until > package_until or issued < _time(key.valid_from, "vault_admin_key_valid_from") or until > key_until:
        _fail("vault_admin_time_invalid")
    sig = _map(row["signature"], _SIGNATURE, "vault_admin_signature")
    if sig["schema"] != SIGNATURE_SCHEMA or _integer(sig["version"], "vault_admin_signature_version") != 1 or sig["algorithm"] != "ed25519" or sig["signer_type"] != "vault-admin": _fail("vault_admin_signature_schema_invalid")
    if (sig["issuer_id"], sig["vault_admin_identity"], sig["key_id"], sig["issued_at"]) != (unsigned["issuer_id"], unsigned["vault_admin_identity"], unsigned["key_id"], unsigned["issued_at"]): _fail("vault_admin_signature_binding_invalid")
    signature_until = _time(sig["valid_until"], "vault_admin_signature_valid_until")
    if signature_until > until or signature_until > package_until: _fail("vault_admin_signature_time_invalid")
    preimage = attestation_preimage(unsigned)
    if _hex(sig["signed_payload_sha256"], "vault_admin_signed_payload_sha256") != hashlib.sha256(preimage).hexdigest(): _fail("vault_admin_signature_digest_invalid")
    signature, public = _b64(sig["signature"], "vault_admin_signature", 64), _b64(key.public_key, "vault_admin_public_key", 32)
    if not Signature.from_bytes(signature).verify(Pubkey.from_bytes(public), preimage): _fail("vault_admin_signature_invalid")
    return VerifiedVaultAdminAttestation(unsigned["issuer_id"], unsigned["vault_admin_identity"], unsigned["key_id"], unsigned["signer_role"], unsigned["evidence_category"], unsigned["artifact_id"], tuple(sorted(subject.items())), hashlib.sha256(preimage).hexdigest(), unsigned["issued_at"], unsigned["valid_until"])
