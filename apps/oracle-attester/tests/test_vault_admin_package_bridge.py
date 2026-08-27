from __future__ import annotations

from types import SimpleNamespace
import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from src.operational_evidence import AuthorizationEvidenceItem
from src.vault_admin_package_bridge import TrustedSignerVaultContext, verify_vault_admin_package_provenance
from solders.keypair import Keypair
from src.vault_admin_attestation import VaultAdminVerificationKey, TrustedVaultSubject, attestation_preimage

NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)
SHA = "a" * 64
def b64(v): return base64.urlsafe_b64encode(v).decode().rstrip("=")
def stamp(v): return v.strftime("%Y-%m-%dT%H:%M:%SZ")


def bridge_inputs(category="vault_auth_principal", role="A"):
    key = Keypair.from_seed(bytes([9]) * 32)
    signer = Keypair.from_seed(bytes([7]) * 32)
    subjects = {"vault_auth_principal": {"vault_auth_principal_id": "vault-auth-a"}, "vault_admin_domain": {"vault_admin_domain_id": "vault-admin-a"}, "vault_account_tenant": {"vault_account_or_tenant_id": "vault-tenant-a"}, "vault_key_identity_version": {"vault_key_name": "vault-key-a", "signer_key_version": 1, "signer_public_key": str(signer.pubkey())}}
    unsigned = {"schema":"PROPHET_VAULT_ADMIN_ATTESTATION_V1","version":1,"environment":"public-devnet","git_sha":"f"*40,"evidence_set_id":"evidence-001","signer_role":role,"evidence_category":category,"artifact_id":"artifact-a","raw_artifact_sha256":SHA,"redacted_artifact_sha256":"b"*64,"issuer_id":"vault-issuer-a","vault_admin_identity":"vault-admin-a","key_id":"vault-key-id","subject":subjects[category],"issued_at":"2026-08-25T11:00:00Z","valid_until":"2026-08-25T13:00:00Z"}
    preimage = attestation_preimage(unsigned)
    signed = {"unsigned_attestation":unsigned,"signature":{"schema":"PROPHET_VAULT_ADMIN_ATTESTATION_SIGNATURE_V1","version":1,"algorithm":"ed25519","signer_type":"vault-admin","issuer_id":"vault-issuer-a","vault_admin_identity":"vault-admin-a","key_id":"vault-key-id","signed_payload_sha256":hashlib.sha256(preimage).hexdigest(),"signature":b64(bytes(key.sign_message(preimage))),"issued_at":unsigned["issued_at"],"valid_until":unsigned["valid_until"]}}
    keys = [VaultAdminVerificationKey("vault-key-id","vault-issuer-a","vault-admin-a",b64(bytes(key.pubkey())),"2026-08-24T12:00:00Z","2026-08-26T12:00:00Z")]
    trusted = TrustedVaultSubject("vault-auth-a","vault-admin-a","vault-tenant-a","vault-key-a",1,str(signer.pubkey()))
    policy = SimpleNamespace(
        vault_admin_verification_keys=tuple(SimpleNamespace(key_id=k.key_id, issuer_id=k.issuer_id, vault_admin_identity=k.vault_admin_identity, public_key=k.public_key, valid_from=k.valid_from, valid_until=k.valid_until) for k in keys),
        deployment_operator_keys=(("operator", "operator", "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"),),
        security_reviewer_keys=(("reviewer", "reviewer", "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"),),
        p0c3e2_verification_keys=(("p0c3e2", "p0c3e2", "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E"),),
        vault_admin_issuers=("vault-issuer-a",), revoked_key_ids=frozenset(), revoked_issuer_ids=frozenset(),
    )
    item = AuthorizationEvidenceItem(role, category, "artifact-a", SHA, "b" * 64, "vault_admin_attestation", "")
    context = TrustedSignerVaultContext(role, trusted.vault_auth_principal_id, trusted.vault_admin_domain_id, trusted.vault_account_or_tenant_id, trusted.vault_key_name, trusted.signer_key_version, trusted.signer_public_key)
    return item, signed, policy, {role: context}


@pytest.mark.parametrize("category", ("vault_auth_principal", "vault_admin_domain", "vault_account_tenant", "vault_key_identity_version"))
@pytest.mark.parametrize("role", ("A", "B"))
def test_bridge_requires_exact_d2_provenance(category, role):
    item, signed, policy, contexts = bridge_inputs(category, role)
    item = AuthorizationEvidenceItem(item.signer_role, item.evidence_category, item.artifact_id, item.raw_artifact_sha256, item.redacted_artifact_sha256, item.provenance_kind, hashlib.sha256(attestation_preimage(signed["unsigned_attestation"])).hexdigest())
    result = verify_vault_admin_package_provenance(item, signed, policy=policy, static_contexts=contexts, expected_environment="public-devnet", expected_git_sha="f" * 40, expected_evidence_set_id="evidence-001", package_valid_until="2026-08-25T13:00:00Z", now=NOW)
    assert result.signer_role == role and result.evidence_category == category


@pytest.mark.parametrize("field,value", (("provenance_kind", "provider_result"), ("provenance_ref", "0" * 64), ("signer_role", "B"), ("evidence_category", "host_vm"), ("artifact_id", "other")))
def test_bridge_rejects_nonexact_package_linkage(field, value):
    item, signed, policy, contexts = bridge_inputs()
    item = AuthorizationEvidenceItem(**{**item.__dict__, field: value})
    with pytest.raises(Exception):
        verify_vault_admin_package_provenance(item, signed, policy=policy, static_contexts=contexts, expected_environment="public-devnet", expected_git_sha="f" * 40, expected_evidence_set_id="evidence-001", package_valid_until="2026-08-25T13:00:00Z", now=NOW)
