"""Active R3C role-local operational-evidence authority derivation.

This module accepts only already verified typed facts.  It does not perform
cryptography, parse permits, or mutate settlement/policy state.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import base64
import hashlib
from typing import Any, Mapping, Sequence

from solders.pubkey import Pubkey
from solders.signature import Signature

from src.operational_evidence import (
    AuthorizationEvidenceItem, EVIDENCE_SCHEMA, ParsedR3CTrustPolicy,
    ProviderResultVerificationKey, VerifiedOperationalEvidence,
    _check_freshness, _timestamp, evidence_preimage, parse_authorization_evidence_inventory, verify_manual_review_package_permit,
    verify_provider_result_v2,
)
from src.vault_admin_package_bridge import (
    TrustedSignerVaultContext, verify_vault_admin_package_provenance,
)


class EffectiveProvenance(str, Enum):
    PROVIDER_ATTESTED = "PROVIDER_ATTESTED"
    VAULT_ADMIN_ATTESTED = "VAULT_ADMIN_ATTESTED"
    MACHINE_VERIFIED = "MACHINE_VERIFIED"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


_ROLES = frozenset(("A", "B"))
_CATEGORIES = frozenset((
    "host_vm", "runtime_principal", "runtime_admin_domain",
    "vault_auth_principal", "vault_admin_domain", "vault_account_tenant",
    "vault_key_identity_version", "rpc_credential_principal", "rpc_provider",
    "rpc_account_project", "journal_storage", "audit_domain", "tls_ingress",
    "worker_reload_concurrency",
))
_PROVIDER_CATEGORIES = frozenset((
    "host_vm", "runtime_principal", "runtime_admin_domain",
    "rpc_credential_principal", "rpc_provider", "rpc_account_project",
    "journal_storage", "audit_domain", "tls_ingress",
))
_VAULT_CATEGORIES = frozenset((
    "vault_auth_principal", "vault_admin_domain", "vault_account_tenant",
    "vault_key_identity_version",
))
_MANUAL_CATEGORIES = frozenset(("journal_storage", "audit_domain"))


class R3CEffectiveAuthorityError(ValueError):
    pass


def _fail(code: str) -> None:
    raise R3CEffectiveAuthorityError(code)


def _target(value: object) -> tuple[str, str, str, str, str]:
    try:
        return (
            value.signer_role, value.evidence_category, value.artifact_id,
            value.raw_artifact_sha256, value.redacted_artifact_sha256,
        )
    except AttributeError:
        _fail("r3c_verified_object_invalid")


@dataclass(frozen=True)
class TrustedStaticR3CCell:
    signer_role: str
    evidence_category: str
    artifact_id: str
    raw_artifact_sha256: str
    redacted_artifact_sha256: str
    workers: int | None = None
    reload: bool | None = None
    execution_concurrency: int | None = None
    vault_key_identity_verified: bool | None = None

    def target(self) -> tuple[str, str, str, str, str]:
        return _target(self)


@dataclass(frozen=True)
class TrustedR3CAuthorityContext:
    """Trusted release and P0C3A runtime facts for the authority facade.

    This context carries no externally verified provenance.  The public
    authority operation consumes raw attestations and performs every verifier
    invocation itself before a fact can influence an effective cell.
    """
    environment: str
    git_sha: str
    evidence_set_id: str
    package_valid_until: str
    provider_keys: tuple[ProviderResultVerificationKey, ...]
    provider_subjects: Mapping[tuple[str, str, str, str, str], Mapping[str, Any]]
    vault_contexts: Mapping[str, TrustedSignerVaultContext]
    static_cells: tuple[TrustedStaticR3CCell, ...]


@dataclass(frozen=True)
class EffectiveR3CCell:
    signer_role: str
    evidence_category: str
    artifact_id: str
    raw_artifact_sha256: str
    redacted_artifact_sha256: str
    provenance: frozenset[EffectiveProvenance]

    def target(self) -> tuple[str, str, str, str, str]:
        return _target(self)


@dataclass(frozen=True)
class EffectiveR3CAuthority:
    policy_id: str
    policy_version: int
    policy_sha256: str
    cells: tuple[EffectiveR3CCell, ...]

    def cell(self, signer_role: str, evidence_category: str) -> EffectiveR3CCell:
        matches = [cell for cell in self.cells if (cell.signer_role, cell.evidence_category) == (signer_role, evidence_category)]
        if len(matches) != 1:
            _fail("r3c_effective_cell_missing")
        return matches[0]


@dataclass(frozen=True)
class R3CAuthorityEvaluation:
    """Descriptive result of one verifier-owned evaluation operation.

    It is deliberately not an authority input: no production callable accepts
    this type, its snapshot, or its boolean as a substitute for raw evidence.
    """
    snapshot: EffectiveR3CAuthority
    public_devnet_sufficient: bool


def _manual_context(policy: ParsedR3CTrustPolicy, context: TrustedR3CAuthorityContext) -> VerifiedOperationalEvidence:
    """Adapt trusted release context to the frozen MR-I2 verifier contract."""
    return VerifiedOperationalEvidence(
        EVIDENCE_SCHEMA, 1, context.evidence_set_id, context.environment,
        context.git_sha, policy.policy_sha256, "0" * 64, "release-context",
        "release-context", "release-context", "release-context", "0" * 64,
        "0" * 64, "0" * 64, "0" * 64, (), (),
        context.package_valid_until, context.package_valid_until,
    )


def _raw_for(
    rows: Mapping[tuple[str, str, str, str, str], Any],
    target: tuple[str, str, str, str, str], name: str,
) -> Any:
    if not isinstance(rows, Mapping) or set(rows) != set(rows.keys()):
        _fail(f"r3c_{name}_inputs_invalid")
    try:
        return rows[target]
    except KeyError:
        _fail(f"r3c_{name}_input_missing")


def derive_r3c_effective_authority(
    raw_signed_package: Any, *, policy: ParsedR3CTrustPolicy,
    raw_provider_results: Mapping[tuple[str, str, str, str, str], Any],
    raw_vault_admin_attestations: Mapping[tuple[str, str, str, str, str], Any],
    trusted_context: TrustedR3CAuthorityContext,
    trusted_now: datetime,
) -> R3CAuthorityEvaluation:
    """The sole public R3C authority facade; it owns package, I2, I3/D2, and MR-I2 verification.

    Callers provide raw evidence only.  The R3C inventory is extracted from the
    authenticated package; constructed ``Verified*`` objects and detached item
    lists are neither parameters nor accepted representations at this boundary.
    """
    if not isinstance(policy, ParsedR3CTrustPolicy):
        _fail("r3c_policy_invalid")
    if not isinstance(trusted_context, TrustedR3CAuthorityContext):
        _fail("r3c_trusted_context_invalid")
    if not isinstance(trusted_now, datetime) or trusted_now.tzinfo is None or trusted_now.utcoffset() is None:
        _fail("r3c_trusted_now_invalid")
    if not isinstance(raw_signed_package, Mapping) or set(raw_signed_package) != {"unsigned_package", "signatures"}:
        _fail("r3c_signed_package_invalid")
    unsigned = raw_signed_package["unsigned_package"]
    try:
        preimage = evidence_preimage(unsigned)
        _generated_at, signed_package_valid_until = _check_freshness(unsigned, trusted_now)
    except Exception as exc:
        raise R3CEffectiveAuthorityError("r3c_signed_package_invalid") from exc
    if (unsigned.get("environment"), unsigned.get("git_sha"), unsigned.get("evidence_set_id")) != (
        trusted_context.environment, trusted_context.git_sha, trusted_context.evidence_set_id,
    ):
        _fail("r3c_signed_package_release_context_invalid")
    if trusted_context.package_valid_until != unsigned["valid_until"]:
        _fail("r3c_signed_package_deadline_binding_invalid")
    if (unsigned.get("trust_policy_id"), unsigned.get("trust_policy_version"), unsigned.get("trust_policy_sha256")) != (policy.policy_id, policy.policy_version, policy.policy_sha256):
        _fail("r3c_signed_package_policy_binding_invalid")
    signatures = raw_signed_package["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 2:
        _fail("r3c_signed_package_signatures_invalid")
    expected_keys = {
        "deployment-operator": {key_id: (identity, public_key) for key_id, identity, public_key in policy.deployment_operator_keys},
        "security-reviewer": {key_id: (identity, public_key) for key_id, identity, public_key in policy.security_reviewer_keys},
    }
    accepted: set[str] = set()
    digest = hashlib.sha256(preimage).hexdigest()
    for signature in signatures:
        if not isinstance(signature, Mapping): _fail("r3c_signed_package_signatures_invalid")
        role, key_id = signature.get("signer_type"), signature.get("key_id")
        if role not in expected_keys or role in accepted or not isinstance(key_id, str): _fail("r3c_signed_package_signatures_invalid")
        key = expected_keys[role].get(key_id)
        if key is None or key_id in policy.revoked_key_ids: _fail("r3c_signed_package_signatures_invalid")
        identity, public_key = key
        if (signature.get("signature_schema"), signature.get("signature_version"), signature.get("algorithm"), signature.get("signer_identity"), signature.get("issuer_identity"), signature.get("signed_payload_sha256")) != ("PROPHET_OPERATED_SIGNER_EVIDENCE_SIGNATURE_V1", 1, "ed25519", identity, identity, digest): _fail("r3c_signed_package_signatures_invalid")
        try:
            issued_at = _timestamp(signature.get("issued_at"), "r3c_signature_issued_at")
            valid_until = _timestamp(signature.get("valid_until"), "r3c_signature_valid_until")
            if (issued_at >= valid_until or issued_at > trusted_now + timedelta(minutes=5)
                    or trusted_now >= valid_until):
                _fail("r3c_signed_package_signature_time_invalid")
            encoded = signature["signature_bytes"]
            raw_signature = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
            raw_key = base64.urlsafe_b64decode(public_key + "=" * ((4 - len(public_key) % 4) % 4))
            if not Signature.from_bytes(raw_signature).verify(Pubkey.from_bytes(raw_key), preimage): _fail("r3c_signed_package_signatures_invalid")
        except R3CEffectiveAuthorityError: raise
        except Exception as exc: raise R3CEffectiveAuthorityError("r3c_signed_package_signatures_invalid") from exc
        accepted.add(role)
    if accepted != set(expected_keys): _fail("r3c_signed_package_signatures_invalid")
    try:
        items = unsigned["redaction_provenance"]["r3c_authorization_items"]
    except (KeyError, TypeError) as exc:
        raise R3CEffectiveAuthorityError("r3c_signed_inventory_missing") from exc
    if not isinstance(items, list): _fail("r3c_signed_inventory_invalid")
    parsed = tuple(parse_authorization_evidence_inventory(items))
    if len(parsed) != 28:
        _fail("r3c_inventory_invalid")
    cells = {_target(item): set() for item in parsed}
    manual_context = _manual_context(policy, trusted_context)
    for item in parsed:
        target = _target(item)
        if item.provenance_kind == "provider_result":
            if item.evidence_category not in _PROVIDER_CATEGORIES or target not in trusted_context.provider_subjects:
                _fail("r3c_provider_input_binding_invalid")
            verified = verify_provider_result_v2(
                _raw_for(raw_provider_results, target, "provider"),
                keys=trusted_context.provider_keys,
                revoked_key_ids=tuple(policy.revoked_key_ids),
                revoked_issuer_ids=tuple(policy.revoked_issuer_ids),
                expected_signer_role=item.signer_role,
                expected_evidence_category=item.evidence_category,
                expected_artifact_id=item.artifact_id,
                expected_raw_artifact_sha256=item.raw_artifact_sha256,
                expected_redacted_artifact_sha256=item.redacted_artifact_sha256,
                expected_subject=trusted_context.provider_subjects[target],
                package_valid_until=unsigned["valid_until"],
                now=trusted_now,
            )
            if _target(verified) != target:
                _fail("r3c_provider_verified_binding_invalid")
            cells[target].add(EffectiveProvenance.PROVIDER_ATTESTED)
        elif item.provenance_kind == "vault_admin_attestation":
            if item.evidence_category not in _VAULT_CATEGORIES:
                _fail("r3c_vault_input_binding_invalid")
            verified = verify_vault_admin_package_provenance(
                item, _raw_for(raw_vault_admin_attestations, target, "vault"),
                policy=policy, static_contexts=trusted_context.vault_contexts,
                expected_environment=trusted_context.environment,
                expected_git_sha=trusted_context.git_sha,
                expected_evidence_set_id=trusted_context.evidence_set_id,
                package_valid_until=unsigned["valid_until"],
                now=trusted_now,
            )
            if _target(verified) != target:
                _fail("r3c_vault_verified_binding_invalid")
            cells[target].add(EffectiveProvenance.VAULT_ADMIN_ATTESTED)
        elif item.provenance_kind == "manual_review_permit":
            if item.evidence_category not in _MANUAL_CATEGORIES:
                _fail("r3c_manual_input_binding_invalid")
            verified = verify_manual_review_package_permit(
                item, policy=policy, verified_evidence=manual_context,
                trusted_now=trusted_now,
            )
            if (_target(verified) != target
                    or (verified.policy_id, verified.policy_version, verified.policy_sha256)
                    != (policy.policy_id, policy.policy_version, policy.policy_sha256)):
                _fail("r3c_manual_verified_binding_invalid")
            cells[target].add(EffectiveProvenance.MANUAL_REVIEW_REQUIRED)
        elif item.provenance_kind == "machine_verified":
            if item.evidence_category != "worker_reload_concurrency":
                _fail("r3c_machine_input_binding_invalid")
        else:
            _fail("r3c_provenance_kind_unsupported")
    seen_static: set[tuple[str, str, str, str, str]] = set()
    for static in trusted_context.static_cells:
        if not isinstance(static, TrustedStaticR3CCell):
            _fail("r3c_static_cell_invalid")
        target = static.target()
        if target not in cells or target in seen_static or static.signer_role not in _ROLES:
            _fail("r3c_static_cell_binding_invalid")
        seen_static.add(target)
        if static.evidence_category == "worker_reload_concurrency":
            if type(static.workers) is int and static.workers == 1 and type(static.reload) is bool and not static.reload and type(static.execution_concurrency) is int and static.execution_concurrency == 1:
                cells[target].add(EffectiveProvenance.MACHINE_VERIFIED)
        elif static.evidence_category == "vault_key_identity_version":
            if static.vault_key_identity_verified is True:
                cells[target].add(EffectiveProvenance.MACHINE_VERIFIED)
        else:
            _fail("r3c_static_category_invalid")
    required = {
        "host_vm": {EffectiveProvenance.PROVIDER_ATTESTED},
        "runtime_principal": {EffectiveProvenance.PROVIDER_ATTESTED},
        "runtime_admin_domain": {EffectiveProvenance.PROVIDER_ATTESTED},
        "vault_auth_principal": {EffectiveProvenance.VAULT_ADMIN_ATTESTED},
        "vault_admin_domain": {EffectiveProvenance.VAULT_ADMIN_ATTESTED},
        "vault_account_tenant": {EffectiveProvenance.VAULT_ADMIN_ATTESTED},
        "vault_key_identity_version": {EffectiveProvenance.MACHINE_VERIFIED, EffectiveProvenance.VAULT_ADMIN_ATTESTED},
        "rpc_credential_principal": {EffectiveProvenance.PROVIDER_ATTESTED},
        "rpc_provider": {EffectiveProvenance.PROVIDER_ATTESTED},
        "rpc_account_project": {EffectiveProvenance.PROVIDER_ATTESTED},
        "tls_ingress": {EffectiveProvenance.PROVIDER_ATTESTED},
        "worker_reload_concurrency": {EffectiveProvenance.MACHINE_VERIFIED},
    }
    sufficient = True
    for role in _ROLES:
        for category, needed in required.items():
            if not needed <= cells[_target(next(item for item in parsed if (item.signer_role, item.evidence_category) == (role, category)))]:
                sufficient = False
        for category in _MANUAL_CATEGORIES:
            options = cells[_target(next(item for item in parsed if (item.signer_role, item.evidence_category) == (role, category)))]
            if not options.intersection({EffectiveProvenance.PROVIDER_ATTESTED, EffectiveProvenance.MANUAL_REVIEW_REQUIRED}):
                sufficient = False
    output = tuple(EffectiveR3CCell(*target, frozenset(provenance)) for target, provenance in sorted(cells.items()))
    return R3CAuthorityEvaluation(EffectiveR3CAuthority(policy.policy_id, policy.policy_version, policy.policy_sha256, output), sufficient)
