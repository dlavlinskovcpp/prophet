"""Non-authorizing, exact package linkage for the frozen D2 primitive."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from src.operational_evidence import AuthorizationEvidenceItem, ParsedR3CTrustPolicy
from src.vault_admin_attestation import (
    AuthoritativeEd25519Key, TrustedVaultSubject, VaultAdminVerificationKey,
    verify_vault_admin_attestation,
)


_CATEGORIES = frozenset(("vault_auth_principal", "vault_admin_domain", "vault_account_tenant", "vault_key_identity_version"))


@dataclass(frozen=True)
class TrustedSignerVaultContext:
    signer_role: str
    vault_auth_principal_id: str
    vault_admin_domain_id: str
    vault_account_or_tenant_id: str
    vault_key_name: str
    signer_key_version: int
    signer_public_key: str

    def subject(self) -> TrustedVaultSubject:
        return TrustedVaultSubject(self.vault_auth_principal_id, self.vault_admin_domain_id, self.vault_account_or_tenant_id, self.vault_key_name, self.signer_key_version, self.signer_public_key)


@dataclass(frozen=True)
class VerifiedVaultAdminPackageProvenance:
    signer_role: str
    evidence_category: str
    artifact_id: str
    raw_artifact_sha256: str
    redacted_artifact_sha256: str
    provenance_ref: str
    vault_admin_issuer_id: str
    vault_admin_key_id: str
    vault_admin_identity: str
    issued_at: str
    valid_until: str


def _external(rows: tuple[tuple[str, str, str], ...]) -> list[AuthoritativeEd25519Key]:
    return [AuthoritativeEd25519Key(key_id, public_key) for key_id, _identity, public_key in rows]


def verify_vault_admin_package_provenance(item: AuthorizationEvidenceItem, attestation: Any, *, policy: ParsedR3CTrustPolicy, static_contexts: Mapping[str, TrustedSignerVaultContext], expected_environment: str, expected_git_sha: str, expected_evidence_set_id: str, package_valid_until: str, now: datetime) -> VerifiedVaultAdminPackageProvenance:
    """Prove D2 provenance for one item; this function grants no authorization."""
    if not isinstance(item, AuthorizationEvidenceItem) or item.provenance_kind != "vault_admin_attestation" or item.evidence_category not in _CATEGORIES:
        raise ValueError("vault_package_item_invalid")
    context = static_contexts.get(item.signer_role) if isinstance(static_contexts, Mapping) else None
    if not isinstance(context, TrustedSignerVaultContext) or context.signer_role != item.signer_role:
        raise ValueError("vault_package_static_context_invalid")
    keys = [VaultAdminVerificationKey(key.key_id, key.issuer_id, key.vault_admin_identity, key.public_key, key.valid_from, key.valid_until) for key in policy.vault_admin_verification_keys]
    result = verify_vault_admin_attestation(
        attestation,
        keys=keys,
        deployment_operator_keys=_external(policy.deployment_operator_keys),
        security_reviewer_keys=_external(policy.security_reviewer_keys),
        p0c3e2_verification_keys=_external(policy.p0c3e2_verification_keys),
        vault_admin_issuers=policy.vault_admin_issuers,
        revoked_key_ids=tuple(policy.revoked_key_ids),
        revoked_issuer_ids=tuple(policy.revoked_issuer_ids),
        trusted_subject=context.subject(),
        expected_environment=expected_environment,
        expected_git_sha=expected_git_sha,
        expected_evidence_set_id=expected_evidence_set_id,
        expected_signer_role=item.signer_role,
        expected_evidence_category=item.evidence_category,
        expected_artifact_id=item.artifact_id,
        expected_raw_artifact_sha256=item.raw_artifact_sha256,
        expected_redacted_artifact_sha256=item.redacted_artifact_sha256,
        package_valid_until=package_valid_until,
        now=now,
    )
    if item.provenance_ref != result.preimage_sha256:
        raise ValueError("vault_package_provenance_ref_invalid")
    return VerifiedVaultAdminPackageProvenance(item.signer_role, item.evidence_category, item.artifact_id, item.raw_artifact_sha256, item.redacted_artifact_sha256, result.preimage_sha256, result.issuer_id, result.key_id, result.vault_admin_identity, result.issued_at, result.valid_until)
