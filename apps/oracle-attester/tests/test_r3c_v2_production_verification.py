"""Frozen R3C V2 inputs through the current raw-evidence authority facade."""
from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.operational_evidence import ProviderResultVerificationKey, parse_r3c_trust_policy
from src.r3c_effective_authority import (
    EffectiveProvenance,
    TrustedR3CAuthorityContext,
    TrustedStaticR3CCell,
    derive_r3c_effective_authority,
)
from src.vault_admin_package_bridge import TrustedSignerVaultContext


NOW = datetime(2026, 8, 25, 12, 30, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parent / "vectors"
V2 = ROOT / "r3c_category_bound_v2"
V1 = ROOT / "r3c_category_bound_v1"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _target(row: dict) -> tuple[str, str, str, str, str]:
    return tuple(row[name] for name in (
        "signer_role", "evidence_category", "artifact_id",
        "raw_artifact_sha256", "redacted_artifact_sha256",
    ))


def _package(name: str) -> dict:
    row = _load(V2 / "packages" / f"{name}.json")
    return {"unsigned_package": row["unsigned_package"], "signatures": row["signatures"]}


def _inputs(package_name: str = "provider-primary"):
    policy_vector = _load(V2 / "trust-policy.json")
    policy = parse_r3c_trust_policy(policy_vector["trust_policy"])
    key = policy_vector["provider_result_verification_key"]
    provider_keys = (ProviderResultVerificationKey(
        key["key_id"], key["issuer_identity"], key["public_key"],
        key["valid_from"], key["valid_until"], tuple(key["provider_policy_ids"]),
    ),)
    providers: dict[tuple[str, str, str, str, str], dict] = {}
    subjects: dict[tuple[str, str, str, str, str], dict] = {}
    for path in sorted((V2 / "provider-results").glob("*.json")):
        row = _load(path)
        unsigned = row["unsigned_result"]
        providers[_target(unsigned)] = {"unsigned_result": unsigned, "signature": row["signature"]}
        subjects[_target(unsigned)] = unsigned["subject"]
    vaults: dict[tuple[str, str, str, str, str], dict] = {}
    vault_contexts: dict[str, TrustedSignerVaultContext] = {}
    for path in sorted((V2 / "vault-admin").glob("*.json")):
        row = _load(path)
        unsigned = row["unsigned_attestation"]
        vaults[_target(unsigned)] = {"unsigned_attestation": unsigned, "signature": row["signature"]}
        if unsigned["evidence_category"] == "vault_key_identity_version":
            subject = unsigned["subject"]
            vault_contexts[unsigned["signer_role"]] = TrustedSignerVaultContext(
                unsigned["signer_role"],
                next(_load(candidate)["unsigned_attestation"]["subject"]["vault_auth_principal_id"]
                     for candidate in (V2 / "vault-admin").glob(f"{unsigned['signer_role'].lower()}-vault_auth_principal.json")),
                next(_load(candidate)["unsigned_attestation"]["subject"]["vault_admin_domain_id"]
                     for candidate in (V2 / "vault-admin").glob(f"{unsigned['signer_role'].lower()}-vault_admin_domain.json")),
                next(_load(candidate)["unsigned_attestation"]["subject"]["vault_account_or_tenant_id"]
                     for candidate in (V2 / "vault-admin").glob(f"{unsigned['signer_role'].lower()}-vault_account_tenant.json")),
                subject["vault_key_name"], subject["signer_key_version"], subject["signer_public_key"],
            )
    static_cells = []
    for fact in _load(V2 / "trusted-static.json")["trusted_static_facts"]["facts"]:
        target = _target(fact)
        if fact["fact_type"] == "worker_runtime":
            static_cells.append(TrustedStaticR3CCell(*target, workers=fact["workers"], reload=fact["reload"], execution_concurrency=fact["execution_concurrency"]))
        else:
            static_cells.append(TrustedStaticR3CCell(*target, vault_key_identity_verified=True))
    package = _package(package_name)
    context = TrustedR3CAuthorityContext(
        package["unsigned_package"]["environment"], package["unsigned_package"]["git_sha"],
        package["unsigned_package"]["evidence_set_id"], package["unsigned_package"]["valid_until"],
        provider_keys, subjects, vault_contexts, tuple(static_cells),
    )
    return policy, package, providers, vaults, context


def _derive(package_name: str = "provider-primary", *, mutate=None):
    policy, package, providers, vaults, context = _inputs(package_name)
    if mutate is not None:
        policy, package, providers, vaults, context = mutate(policy, package, providers, vaults, context)
    return derive_r3c_effective_authority(
        package, policy=policy, raw_provider_results=providers,
        raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW,
    )


@pytest.mark.parametrize("package_name", ("provider-primary", "manual-review-alternative"))
def test_v2_frozen_package_reaches_current_raw_evidence_authority(package_name):
    result = _derive(package_name)
    assert result.public_devnet_sufficient
    assert len(result.snapshot.cells) == 28
    for role in ("A", "B"):
        assert EffectiveProvenance.MACHINE_VERIFIED in result.snapshot.cell(role, "worker_reload_concurrency").provenance
        assert {EffectiveProvenance.MACHINE_VERIFIED, EffectiveProvenance.VAULT_ADMIN_ATTESTED} <= result.snapshot.cell(role, "vault_key_identity_version").provenance


def test_v2_provider_and_vault_vectors_all_verify_in_current_authority_path():
    result = _derive()
    assert sum(EffectiveProvenance.PROVIDER_ATTESTED in cell.provenance for cell in result.snapshot.cells) == 18
    assert sum(EffectiveProvenance.VAULT_ADMIN_ATTESTED in cell.provenance for cell in result.snapshot.cells) == 8


def test_v2_manual_permits_and_historical_mr_i1_linkage_verify_when_selected():
    result = _derive("manual-review-alternative")
    for role, category in (("A", "journal_storage"), ("A", "audit_domain"), ("B", "journal_storage"), ("B", "audit_domain")):
        assert EffectiveProvenance.MANUAL_REVIEW_REQUIRED in result.snapshot.cell(role, category).provenance


@pytest.mark.parametrize("kind,role,category", (
    ("provider", "A", "host_vm"), ("vault", "A", "vault_auth_principal"),
))
def test_valid_package_signatures_do_not_authorize_missing_external_evidence(kind, role, category):
    def mutate(policy, package, providers, vaults, context):
        rows = providers if kind == "provider" else vaults
        key = next(key for key in rows if key[:2] == (role, category))
        rows.pop(key)
        return policy, package, providers, vaults, context
    with pytest.raises(ValueError):
        _derive(mutate=mutate)


@pytest.mark.parametrize("from_role,to_role", (("A", "B"), ("B", "A")))
def test_v2_provider_role_replay_rejects(from_role, to_role):
    def mutate(policy, package, providers, vaults, context):
        source = next(key for key in providers if key[:2] == (from_role, "host_vm"))
        destination = next(key for key in providers if key[:2] == (to_role, "host_vm"))
        providers[destination] = providers[source]
        return policy, package, providers, vaults, context
    with pytest.raises(ValueError):
        _derive(mutate=mutate)


@pytest.mark.parametrize("from_category,to_category", (("journal_storage", "audit_domain"), ("rpc_provider", "rpc_account_project")))
def test_v2_provider_category_replay_rejects(from_category, to_category):
    def mutate(policy, package, providers, vaults, context):
        source = next(key for key in providers if key[:2] == ("A", from_category))
        destination = next(key for key in providers if key[:2] == ("A", to_category))
        providers[destination] = providers[source]
        return policy, package, providers, vaults, context
    with pytest.raises(ValueError):
        _derive(mutate=mutate)


@pytest.mark.parametrize("field", ("artifact_id", "raw_artifact_sha256", "redacted_artifact_sha256", "provenance_ref"))
@pytest.mark.parametrize("kind,package_name,role,category", (
    ("provider", "provider-primary", "A", "host_vm"),
    ("vault", "provider-primary", "A", "vault_auth_principal"),
    ("manual", "manual-review-alternative", "A", "audit_domain"),
))
def test_v2_signed_item_binding_mutations_reject(kind, package_name, role, category, field):
    def mutate(policy, package, providers, vaults, context):
        items = package["unsigned_package"]["redaction_provenance"]["r3c_authorization_items"]
        item = next(row for row in items if row["signer_role"] == role and row["evidence_category"] == category)
        item[field] = "0" * 64 if field.endswith("sha256") or field == "provenance_ref" else "substituted-artifact"
        return policy, package, providers, vaults, context
    with pytest.raises(ValueError):
        _derive(package_name, mutate=mutate)


@pytest.mark.parametrize("mutation", ("missing_a", "missing_b", "duplicate", "same_role_reuse", "cross_role_reuse"))
def test_v2_inventory_structural_mutations_reject(mutation):
    def mutate(policy, package, providers, vaults, context):
        items = package["unsigned_package"]["redaction_provenance"]["r3c_authorization_items"]
        if mutation == "missing_a":
            items[:] = [item for item in items if item["signer_role"] != "A"]
        elif mutation == "missing_b":
            items[:] = [item for item in items if item["signer_role"] != "B"]
        elif mutation == "duplicate":
            items[-1] = copy.deepcopy(items[0])
        elif mutation == "same_role_reuse":
            left, right = next(item for item in items if item["signer_role"] == "A" and item["evidence_category"] == "host_vm"), next(item for item in items if item["signer_role"] == "A" and item["evidence_category"] == "runtime_principal")
            right["artifact_id"] = left["artifact_id"]
        else:
            left, right = next(item for item in items if item["signer_role"] == "A"), next(item for item in items if item["signer_role"] == "B")
            right["artifact_id"] = left["artifact_id"]
        return policy, package, providers, vaults, context
    with pytest.raises(ValueError):
        _derive(mutate=mutate)


@pytest.mark.parametrize("role,remove_static,remove_vault,other_role", (
    ("A", True, False, None), ("A", False, True, None),
    ("B", True, False, None), ("B", False, True, None),
    ("A", True, False, "B"), ("B", True, False, "A"),
))
def test_v2_vault_key_compound_requirements_are_role_local(role, remove_static, remove_vault, other_role):
    def mutate(policy, package, providers, vaults, context):
        if remove_static:
            context = replace(context, static_cells=tuple(cell for cell in context.static_cells if not (cell.signer_role == role and cell.evidence_category == "vault_key_identity_version")))
        if remove_vault:
            key = next(key for key in vaults if key[:2] == (role, "vault_key_identity_version"))
            vaults.pop(key)
        if other_role:
            source = next(key for key in vaults if key[:2] == (other_role, "vault_key_identity_version"))
            destination = next(key for key in vaults if key[:2] == (role, "vault_key_identity_version"))
            vaults[destination] = vaults[source]
        return policy, package, providers, vaults, context
    with pytest.raises(ValueError) if remove_vault or other_role else pytest.raises(AssertionError):
        result = _derive(mutate=mutate)
        assert result.public_devnet_sufficient


@pytest.mark.parametrize("mutation", ("policy", "provenance", "expired"))
def test_v2_manual_review_mutations_leave_minima_insufficient(mutation):
    def mutate(policy, package, providers, vaults, context):
        if mutation == "policy":
            policy = replace(policy, manual_review_permits=tuple(permit for permit in policy.manual_review_permits if (permit.signer_role, permit.evidence_category) != ("A", "audit_domain")))
        elif mutation == "provenance":
            item = next(item for item in package["unsigned_package"]["redaction_provenance"]["r3c_authorization_items"] if (item["signer_role"], item["evidence_category"]) == ("A", "audit_domain"))
            item["provenance_ref"] = "0" * 64
        else:
            context = replace(context, package_valid_until="2026-08-25T12:15:00Z")
        return policy, package, providers, vaults, context
    with pytest.raises(ValueError):
        _derive("manual-review-alternative", mutate=mutate)


def test_v1_is_failed_immutable_candidate_and_cannot_be_current_authority():
    manifest = _load(V2 / "manifest.json")
    assert manifest["failed_candidate_supersession"]["status"] == "FAILED IMMUTABLE CANDIDATE — SUPERSEDED BEFORE ACCEPTANCE"
    legacy = _load(V1 / "packages" / "provider-primary.json")
    policy, _, providers, vaults, context = _inputs()
    with pytest.raises(ValueError):
        derive_r3c_effective_authority({"unsigned_package": legacy["unsigned_package"], "signatures": legacy["signatures"]}, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW)


def test_historical_r1_marker_is_superseded_and_has_no_current_authority():
    manifest = _load(V2 / "manifest.json")
    historical = manifest["historical_supersession"]
    assert historical["marker"] == "SUPERSEDED BY R3C CATEGORY-BOUND CRYPTOGRAPHIC VECTOR SET"
    assert (Path(__file__).resolve().parents[3] / historical["historical_fixture"]).is_file()


def test_immutable_d2_attestation_cannot_supply_v2_release_context():
    policy, package, providers, vaults, context = _inputs()
    target = next(key for key in vaults if key[:2] == ("A", "vault_key_identity_version"))
    historical = _load(ROOT / "vault_admin_attestation_v1.json")
    vaults[target] = {
        "unsigned_attestation": historical["unsigned_attestation"],
        "signature": historical["signature_envelope"],
    }
    with pytest.raises(ValueError):
        derive_r3c_effective_authority(
            package, policy=policy, raw_provider_results=providers,
            raw_vault_admin_attestations=vaults, trusted_context=context, trusted_now=NOW,
        )
