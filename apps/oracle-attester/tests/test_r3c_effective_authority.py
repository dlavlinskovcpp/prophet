"""I4 origin-bound authority regressions."""
from __future__ import annotations

import base64
import hashlib
import runpy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from solders.keypair import Keypair

import src.r3c_effective_authority as authority_module
from src.operational_evidence import BASELINE_GIT_SHA, AuthorizationEvidenceItem, ProviderResultVerificationKey, VerifiedManualReviewPermit, VerifiedProviderResultV2, parse_r3c_trust_policy, result_v2_preimage
from src.r3c_effective_authority import EffectiveProvenance, EffectiveR3CAuthority, EffectiveR3CCell, TrustedR3CAuthorityContext, TrustedStaticR3CCell, derive_r3c_effective_authority
from src.vault_admin_attestation import attestation_preimage
from src.vault_admin_package_bridge import TrustedSignerVaultContext, VerifiedVaultAdminPackageProvenance

NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)
I1 = runpy.run_path(str(Path(__file__).with_name("test_operational_evidence_r3c_i1.py")))
CATEGORIES = ("host_vm", "runtime_principal", "runtime_admin_domain", "vault_auth_principal", "vault_admin_domain", "vault_account_tenant", "vault_key_identity_version", "rpc_credential_principal", "rpc_provider", "rpc_account_project", "journal_storage", "audit_domain", "tls_ingress", "worker_reload_concurrency")
PROVIDER = {"host_vm", "runtime_principal", "runtime_admin_domain", "rpc_credential_principal", "rpc_provider", "rpc_account_project", "journal_storage", "audit_domain", "tls_ingress"}
VAULT = {"vault_auth_principal", "vault_admin_domain", "vault_account_tenant", "vault_key_identity_version"}
SUBJECT = {"host_vm": "host_id", "runtime_principal": "runtime_principal_id", "runtime_admin_domain": "runtime_admin_domain_id", "rpc_credential_principal": "rpc_credential_principal_id", "rpc_provider": "rpc_provider_id", "rpc_account_project": "rpc_account_project_id", "journal_storage": "journal_storage_id", "audit_domain": "audit_domain_id", "tls_ingress": "tls_ingress_id"}

def b64(v: bytes) -> str: return base64.urlsafe_b64encode(v).decode().rstrip("=")
def h(v: str) -> str: return hashlib.sha256(v.encode()).hexdigest()
def target(i): return (i.signer_role, i.evidence_category, i.artifact_id, i.raw_artifact_sha256, i.redacted_artifact_sha256)

def signed_package(inventory, policy):
    """Test-only authenticated envelope; authority items live inside its signature."""
    def signer(role, seed):
        key = Keypair.from_seed(bytes([seed]) * 32); suffix = role.lower()
        return {"signer_role":role,"signer_id":f"signer-{suffix}","signer_public_key":str(key.pubkey()),"host":f"host-{suffix}","runtime_principal":f"runtime-{suffix}","runtime_admin_domain":f"admin-{suffix}","service_instance":f"service-{suffix}","vault_auth_principal":f"vault-auth-{suffix}","vault_admin_domain":f"vault-admin-{suffix}","vault_tenant":f"vault-tenant-{suffix}","rpc_credential_principal":f"rpc-credential-{suffix}","rpc_provider":f"rpc-provider-{suffix}","rpc_account":f"rpc-account-{suffix}","journal_storage":f"journal-{suffix}","audit_domain":f"audit-{suffix}","tls_termination":f"tls-{suffix}"}
    stamp = "2026-08-25T11:00:00Z"; until = "2026-08-25T13:00:00Z"
    artifacts = [{"artifact_id":f"envelope-{r}","artifact_sha256":h(f"artifact-{r}"),"media_type":"application-json","role":"infrastructure","signer_role":r,"subject_account_scope":f"scope-{r}","evidence_set_id":"evidence-001","environment":"public-devnet","git_sha":BASELINE_GIT_SHA,"generated_at":stamp,"valid_until":until,"raw_artifact_sha256":h(f"raw-envelope-{r}"),"redacted_artifact_sha256":h(f"redacted-envelope-{r}"),"redaction_profile_version":"redaction-v1","provider_issuer_identity":"provider-a","provider_attestation_id":f"envelope-provider-{r}","provider_policy_id":"provider-policy-a"} for r in ("A","B")]
    unsigned = {"schema":"PROPHET_OPERATED_SIGNER_EVIDENCE_V1","version":1,"environment":"public-devnet","git_sha":BASELINE_GIT_SHA,"trust_policy_id":policy.policy_id,"trust_policy_version":policy.policy_version,"trust_policy_sha256":policy.policy_sha256,"evidence_set_id":"evidence-001","generated_at":stamp,"valid_until":until,"service_config_fingerprints":{"A":"a"*64,"B":"b"*64},"deployment_manifest_fingerprints":{"A":"c"*64,"B":"d"*64},"signers":[signer("A",9),signer("B",10)],"artifacts":artifacts,"independence_assertions":{},"expected_evidence_classifications":{},"redaction_provenance":{"r3c_authorization_items":[i.__dict__ for i in inventory]}}
    from src.operational_evidence import evidence_preimage
    preimage = evidence_preimage(unsigned); digest = hashlib.sha256(preimage).hexdigest()
    sigs=[]
    for role,identity,key_id,seed in (("deployment-operator","operator-a","operator-key",1),("security-reviewer","reviewer-a","reviewer-key",2)):
        sigs.append({"signature_schema":"PROPHET_OPERATED_SIGNER_EVIDENCE_SIGNATURE_V1","signature_version":1,"algorithm":"ed25519","signer_type":role,"signer_identity":identity,"issuer_identity":identity,"key_id":key_id,"signed_payload_sha256":digest,"signature_bytes":b64(bytes(Keypair.from_seed(bytes([seed])*32).sign_message(preimage))),"issued_at":stamp,"valid_until":until})
    return {"unsigned_package":unsigned,"signatures":sigs}

def provider_raw(i, subject, key):
    unsigned = {"schema":"PROPHET_PROVIDER_VERIFICATION_RESULT_V2","version":2,"provider_attestation_id":f"provider-{i.signer_role}-{i.evidence_category}","issuer_identity":"provider-a","subject_account_scope":"scope-a","environment":"public-devnet","git_sha":BASELINE_GIT_SHA,"evidence_set_id":"evidence-001","signer_role":i.signer_role,"evidence_category":i.evidence_category,"artifact_id":i.artifact_id,"raw_artifact_sha256":i.raw_artifact_sha256,"redacted_artifact_sha256":i.redacted_artifact_sha256,"provider_policy_id":"provider-policy-a","issued_at":"2026-08-25T11:00:00Z","verified_at":"2026-08-25T11:00:00Z","valid_until":"2026-08-25T13:00:00Z","result":"VERIFIED","subject":subject}
    return {"unsigned_result":unsigned,"signature":{"signature_schema":"PROPHET_PROVIDER_VERIFICATION_RESULT_SIGNATURE_V1","signature_version":1,"algorithm":"ed25519","key_id":"provider-key","signature_bytes":b64(bytes(key.sign_message(result_v2_preimage(unsigned))))}}

def vault_raw(i, role, key, signer):
    subjects = {"vault_auth_principal":{"vault_auth_principal_id":f"vault-auth-{role}"},"vault_admin_domain":{"vault_admin_domain_id":f"vault-admin-{role}"},"vault_account_tenant":{"vault_account_or_tenant_id":f"vault-tenant-{role}"},"vault_key_identity_version":{"vault_key_name":f"vault-key-{role}","signer_key_version":1,"signer_public_key":str(signer.pubkey())}}
    unsigned = {"schema":"PROPHET_VAULT_ADMIN_ATTESTATION_V1","version":1,"environment":"public-devnet","git_sha":BASELINE_GIT_SHA,"evidence_set_id":"evidence-001","signer_role":role,"evidence_category":i.evidence_category,"artifact_id":i.artifact_id,"raw_artifact_sha256":i.raw_artifact_sha256,"redacted_artifact_sha256":i.redacted_artifact_sha256,"issuer_id":"vault-admin-issuer-a","vault_admin_identity":"vault-admin-a","key_id":"vault-admin-key","subject":subjects[i.evidence_category],"issued_at":"2026-08-25T11:00:00Z","valid_until":"2026-08-25T13:00:00Z"}
    preimage = attestation_preimage(unsigned)
    return {"unsigned_attestation":unsigned,"signature":{"schema":"PROPHET_VAULT_ADMIN_ATTESTATION_SIGNATURE_V1","version":1,"algorithm":"ed25519","signer_type":"vault-admin","issuer_id":"vault-admin-issuer-a","vault_admin_identity":"vault-admin-a","key_id":"vault-admin-key","signed_payload_sha256":hashlib.sha256(preimage).hexdigest(),"signature":b64(bytes(key.sign_message(preimage))),"issued_at":unsigned["issued_at"],"valid_until":unsigned["valid_until"]}}

def fixture(manual=False):
    inventory = []
    for role in ("A", "B"):
        for category in CATEGORIES:
            kind = "machine_verified" if category == "worker_reload_concurrency" else "manual_review_permit" if manual and category in {"journal_storage", "audit_domain"} else "vault_admin_attestation" if category in VAULT else "provider_result"
            inventory.append(AuthorizationEvidenceItem(role, category, f"artifact-{role}-{category}", h(f"raw-{role}-{category}"), h(f"redacted-{role}-{category}"), kind, "pending"))
    raw_policy = I1["policy"]()
    raw_policy["manual_review_permits"] = [{"schema":"PROPHET_MANUAL_REVIEW_PERMIT_V1","version":1,"permit_id":f"permit-{i.signer_role}-{i.evidence_category}","environment":"public-devnet","git_sha":BASELINE_GIT_SHA,"evidence_set_id":"evidence-001","signer_role":i.signer_role,"evidence_category":i.evidence_category,"artifact_id":i.artifact_id,"raw_artifact_sha256":i.raw_artifact_sha256,"redacted_artifact_sha256":i.redacted_artifact_sha256,"valid_from":"2026-08-25T11:00:00Z","valid_until":"2026-08-25T13:00:00Z"} for i in inventory if i.provenance_kind == "manual_review_permit"]
    policy = parse_r3c_trust_policy(raw_policy)
    permits = {(p.signer_role,p.evidence_category):p for p in policy.manual_review_permits}
    inventory = [replace(i, provenance_ref=permits[(i.signer_role,i.evidence_category)].provenance_ref) if i.provenance_kind == "manual_review_permit" else i for i in inventory]
    pk, vk = Keypair.from_seed(bytes([30])*32), Keypair.from_seed(bytes([4])*32)
    providers, subjects, vaults, contexts = {}, {}, {}, {}
    for role in ("A", "B"):
        signer = Keypair.from_seed(bytes([7 if role == "A" else 8])*32)
        contexts[role] = TrustedSignerVaultContext(role, f"vault-auth-{role}", f"vault-admin-{role}", f"vault-tenant-{role}", f"vault-key-{role}", 1, str(signer.pubkey()))
        for n, i in enumerate(inventory):
            if i.signer_role != role: continue
            if i.provenance_kind == "provider_result":
                subject = {SUBJECT[i.evidence_category]:f"{i.evidence_category}-{role}"}; subjects[target(i)] = subject; providers[target(i)] = provider_raw(i, subject, pk)
            elif i.provenance_kind == "vault_admin_attestation":
                raw = vault_raw(i, role, vk, signer); vaults[target(i)] = raw
                inventory[n] = replace(i, provenance_ref=hashlib.sha256(attestation_preimage(raw["unsigned_attestation"])).hexdigest())
    by_cell = {(i.signer_role,i.evidence_category):i for i in inventory}
    static = []
    for role in ("A", "B"):
        worker, key_i = by_cell[(role,"worker_reload_concurrency")], by_cell[(role,"vault_key_identity_version")]
        static += [TrustedStaticR3CCell(*target(worker), workers=1, reload=False, execution_concurrency=1), TrustedStaticR3CCell(*target(key_i), vault_key_identity_verified=True)]
    context = TrustedR3CAuthorityContext("public-devnet", BASELINE_GIT_SHA, "evidence-001", "2026-08-25T13:00:00Z", (ProviderResultVerificationKey("provider-key","provider-a",b64(bytes(pk.pubkey())),"2026-08-24T12:00:00Z","2026-08-26T12:00:00Z",("provider-policy-a",)),), subjects, contexts, tuple(static))
    return policy, inventory, providers, vaults, context

def derive(manual=False, mutate=None):
    policy, inventory, providers, vaults, context = fixture(manual)
    if mutate: policy, inventory, providers, vaults, context = mutate(policy, inventory, providers, vaults, context)
    return derive_r3c_effective_authority(signed_package(inventory, policy), policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW)

def test_full_a_b_role_local_matrix_is_inspectable_and_sufficient():
    evaluation = derive(); authority = evaluation.snapshot; assert len(authority.cells) == 28 and evaluation.public_devnet_sufficient
    for role in ("A", "B"):
        assert EffectiveProvenance.MACHINE_VERIFIED in authority.cell(role,"worker_reload_concurrency").provenance
        assert {EffectiveProvenance.MACHINE_VERIFIED,EffectiveProvenance.VAULT_ADMIN_ATTESTED} <= authority.cell(role,"vault_key_identity_version").provenance

@pytest.mark.parametrize("role,category", [(r,c) for r in ("A","B") for c in CATEGORIES])
def test_each_single_required_raw_evidence_removal_rejects(role, category):
    def remove(policy, inventory, providers, vaults, context):
        i = next(x for x in inventory if (x.signer_role,x.evidence_category)==(role,category))
        if i.provenance_kind == "provider_result": providers.pop(target(i))
        elif i.provenance_kind == "vault_admin_attestation": vaults.pop(target(i))
        else: inventory.remove(i)
        return policy, inventory, providers, vaults, context
    with pytest.raises(Exception): derive(mutate=remove)

def test_actual_mr_i2_is_the_journal_audit_alternative(): assert derive(manual=True).public_devnet_sufficient

def test_vault_key_requires_machine_and_vault_admin_per_role():
    def remove_static(policy, inventory, providers, vaults, context): return policy, inventory, providers, vaults, replace(context, static_cells=tuple(x for x in context.static_cells if not (x.signer_role=="A" and x.evidence_category=="vault_key_identity_version")))
    assert not derive(mutate=remove_static).public_devnet_sufficient

def test_directly_constructed_verified_objects_cannot_authorize():
    policy, inventory, providers, vaults, context = fixture(); i = next(x for x in inventory if x.provenance_kind=="provider_result")
    providers[target(i)] = VerifiedProviderResultV2(*target(i), (), "forged", "forged", "2026-08-25T11:00:00Z", "2026-08-25T13:00:00Z")
    with pytest.raises(Exception): derive_r3c_effective_authority(inventory, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW)
    policy, inventory, providers, vaults, context = fixture(); i = next(x for x in inventory if x.provenance_kind=="vault_admin_attestation")
    vaults[target(i)] = VerifiedVaultAdminPackageProvenance(*target(i), "a"*64, "forged", "forged", "forged", "2026-08-25T11:00:00Z", "2026-08-25T13:00:00Z")
    with pytest.raises(Exception): derive_r3c_effective_authority(inventory, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW)
    policy, inventory, providers, vaults, context = fixture(True); i = next(x for x in inventory if x.provenance_kind=="manual_review_permit")
    fake = VerifiedManualReviewPermit("fake",policy.policy_id,policy.policy_version,policy.policy_sha256,"public-devnet",BASELINE_GIT_SHA,"evidence-001",*target(i),"a"*64,"2026-08-25T11:00:00Z","2026-08-25T13:00:00Z")
    with pytest.raises(TypeError): derive_r3c_effective_authority(inventory, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW, manual_review_permits=(fake,))

def test_no_verified_fact_to_effective_authority_helper_exists():
    assert not hasattr(authority_module, "_derive_effective_from_locally_verified")

def test_forged_complete_effective_snapshot_is_audit_only_and_cannot_be_submitted():
    genuine = derive().snapshot
    forged = EffectiveR3CAuthority(
        genuine.policy_id, genuine.policy_version, genuine.policy_sha256,
        tuple(EffectiveR3CCell(*target(cell), cell.provenance) for cell in genuine.cells),
    )
    assert not hasattr(forged, "satisfies_public_devnet_minima")
    policy, inventory, providers, vaults, context = fixture()
    with pytest.raises(TypeError):
        derive_r3c_effective_authority(inventory, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW, effective_authority=forged)

@pytest.mark.parametrize("forged_parameter", ("provider_results", "vault_provenance", "manual_review_permits"))
def test_public_authority_facade_rejects_verified_fact_parameters(forged_parameter):
    policy, inventory, providers, vaults, context = fixture()
    with pytest.raises(TypeError):
        derive_r3c_effective_authority(inventory, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW, **{forged_parameter: ()})

def test_cross_role_raw_replay_rejects_not_pool():
    def replay(policy, inventory, providers, vaults, context):
        a,b = next(k for k in providers if k[:2]==("A","host_vm")),next(k for k in providers if k[:2]==("B","host_vm")); providers[a],providers[b]=providers[b],providers[a]; return policy,inventory,providers,vaults,context
    with pytest.raises(Exception): derive(mutate=replay)


def test_signed_item_tampering_rejects():
    policy, inventory, providers, vaults, context = fixture()
    package = signed_package(inventory, policy)
    package["unsigned_package"]["redaction_provenance"]["r3c_authorization_items"][0]["artifact_id"] = "detached-artifact"
    with pytest.raises(Exception):
        derive_r3c_effective_authority(package, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW)


def test_detached_single_field_inventory_substitution_is_impossible():
    policy, inventory, providers, vaults, context = fixture()
    detached = [replace(item, provenance_ref="detached-ref") if index == 0 else item for index, item in enumerate(inventory)]
    with pytest.raises(TypeError):
        derive_r3c_effective_authority(signed_package(inventory, policy), detached_inventory=detached, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW)


def test_detached_full_inventory_replacement_is_impossible():
    policy, inventory, providers, vaults, context = fixture()
    replacement = [replace(item, artifact_id=f"replacement-{index}") for index, item in enumerate(inventory)]
    with pytest.raises(TypeError):
        derive_r3c_effective_authority(signed_package(inventory, policy), inventory=replacement, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW)


def test_valid_legacy_envelope_claims_cannot_replace_missing_r3c_evidence():
    policy, inventory, providers, vaults, context = fixture()
    missing = next(item for item in inventory if item.provenance_kind == "provider_result")
    providers.pop(target(missing))
    with pytest.raises(Exception):
        derive_r3c_effective_authority(signed_package(inventory, policy), policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW)
