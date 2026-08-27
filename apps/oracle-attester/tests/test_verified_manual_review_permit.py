"""MR-I2-I1 current-policy manual-review permit verification regressions."""
from __future__ import annotations

import hashlib
import runpy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.operational_evidence import (
    BASELINE_GIT_SHA,
    EVIDENCE_SCHEMA,
    AuthorizationEvidenceItem,
    OperationalEvidenceError,
    VerifiedOperationalEvidence,
    parse_r3c_trust_policy,
    verify_manual_review_package_permit,
)


NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)
_I1 = runpy.run_path(str(Path(__file__).with_name("test_operational_evidence_r3c_i1.py")))


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def permit(role: str = "A", category: str = "journal_storage") -> dict:
    return {
        "schema": "PROPHET_MANUAL_REVIEW_PERMIT_V1", "version": 1,
        "permit_id": f"permit-{role}-{category}", "environment": "public-devnet",
        "git_sha": BASELINE_GIT_SHA, "evidence_set_id": "evidence-001",
        "signer_role": role, "evidence_category": category,
        "artifact_id": f"artifact-{role}-{category}",
        "raw_artifact_sha256": _hash(f"raw-{role}-{category}"),
        "redacted_artifact_sha256": _hash(f"redacted-{role}-{category}"),
        "valid_from": "2026-08-25T11:00:00Z", "valid_until": "2026-08-25T13:00:00Z",
    }


def policy(*permits: dict):
    value = _I1["policy"]()
    value["manual_review_permits"] = list(permits)
    return parse_r3c_trust_policy(value)


def context(current_policy, *, environment="public-devnet", git_sha=BASELINE_GIT_SHA, evidence_set_id="evidence-001"):
    return VerifiedOperationalEvidence(
        schema=EVIDENCE_SCHEMA, version=1, evidence_set_id=evidence_set_id,
        environment=environment, git_sha=git_sha,
        trust_policy_sha256=current_policy.policy_sha256,
        signed_payload_sha256="c" * 64, operator_identity="operator-a", operator_key_id="operator-key",
        reviewer_identity="reviewer-a", reviewer_key_id="reviewer-key",
        signer_a_service_config_fingerprint="d" * 64, signer_b_service_config_fingerprint="e" * 64,
        signer_a_deployment_manifest_fingerprint="f" * 64, signer_b_deployment_manifest_fingerprint="0" * 64,
        independence_assertions=(), classifications=(),
        generated_at="2026-08-25T11:00:00Z", valid_until="2026-08-25T13:00:00Z",
    )


def item(current_policy, role="A", category="journal_storage"):
    matched = next(p for p in current_policy.manual_review_permits if (p.signer_role, p.evidence_category) == (role, category))
    return AuthorizationEvidenceItem(
        matched.signer_role, matched.evidence_category, matched.artifact_id,
        matched.raw_artifact_sha256, matched.redacted_artifact_sha256,
        "manual_review_permit", matched.provenance_ref,
    )


def verify(current_policy, package_item=None, verified_context=None, now=NOW):
    package_item = package_item or item(current_policy)
    verified_context = verified_context or context(current_policy)
    return verify_manual_review_package_permit(
        package_item, policy=current_policy, verified_evidence=verified_context, trusted_now=now,
    )


@pytest.mark.parametrize("role,category", (("A", "journal_storage"), ("B", "journal_storage"), ("A", "audit_domain"), ("B", "audit_domain")))
def test_current_policy_exact_permit_verifies_for_each_admitted_target(role, category):
    current = policy(*(permit(r, c) for r in ("A", "B") for c in ("journal_storage", "audit_domain")))
    result = verify(current, item(current, role, category))
    assert (result.signer_role, result.evidence_category) == (role, category)


@pytest.mark.parametrize("field,value", (
    ("provenance_kind", "provider_result"), ("provenance_ref", "0" * 64),
    ("signer_role", "B"), ("evidence_category", "audit_domain"),
    ("artifact_id", "other-artifact"), ("raw_artifact_sha256", "c" * 64),
    ("redacted_artifact_sha256", "d" * 64),
))
def test_package_item_single_binding_mutations_reject(field, value):
    current = policy(permit())
    with pytest.raises(OperationalEvidenceError):
        verify(current, replace(item(current), **{field: value}))


@pytest.mark.parametrize("field,value", (
    ("environment", "other-environment"), ("git_sha", "b" * 40), ("evidence_set_id", "other-evidence-set"),
))
def test_release_context_single_binding_mutations_reject(field, value):
    current = policy(permit())
    with pytest.raises(OperationalEvidenceError):
        verify(current, verified_context=replace(context(current), **{field: value}))


def test_absent_and_successor_removed_policy_permits_reject():
    original = policy(permit())
    package_item = item(original)
    absent = policy()
    with pytest.raises(OperationalEvidenceError):
        verify(absent, package_item, context(absent))
    successor_raw = _I1["policy"]()
    successor_raw["policy_version"] = 3
    successor_raw["manual_review_permits"] = []
    successor = parse_r3c_trust_policy(successor_raw)
    with pytest.raises(OperationalEvidenceError):
        verify(successor, package_item, context(successor))


def test_detached_permit_and_ambiguous_current_policy_cannot_verify():
    current = policy(permit())
    with pytest.raises(TypeError):
        verify_manual_review_package_permit(item(current), policy=current, verified_evidence=context(current), trusted_now=NOW, detached_permit=current.manual_review_permits[0])
    ambiguous = replace(current, manual_review_permits=(current.manual_review_permits[0], current.manual_review_permits[0]))
    with pytest.raises(OperationalEvidenceError):
        verify(ambiguous, item(current), context(ambiguous))


@pytest.mark.parametrize("now,accepted", (
    (datetime(2026, 8, 25, 10, 59, 59, tzinfo=timezone.utc), False),
    (datetime(2026, 8, 25, 11, 0, tzinfo=timezone.utc), True),
    (NOW, True),
    (datetime(2026, 8, 25, 13, 0, tzinfo=timezone.utc), False),
    (datetime(2026, 8, 25, 13, 0, 1, tzinfo=timezone.utc), False),
))
def test_trusted_now_interval_boundaries(now, accepted):
    current = policy(permit())
    if accepted:
        assert verify(current, now=now).permit_id == "permit-A-journal_storage"
    else:
        with pytest.raises(OperationalEvidenceError):
            verify(current, now=now)


def test_naive_trusted_now_rejects():
    current = policy(permit())
    with pytest.raises(OperationalEvidenceError):
        verify(current, now=datetime(2026, 8, 25, 12))


def test_verified_result_is_immutable_exactly_policy_bound_and_side_effect_free():
    current = policy(permit())
    package_item = item(current)
    verified_context = context(current)
    result = verify(current, package_item, verified_context)
    assert (result.policy_id, result.policy_version, result.policy_sha256) == (current.policy_id, current.policy_version, current.policy_sha256)
    assert (result.artifact_id, result.raw_artifact_sha256, result.redacted_artifact_sha256, result.provenance_ref) == (package_item.artifact_id, package_item.raw_artifact_sha256, package_item.redacted_artifact_sha256, package_item.provenance_ref)
    with pytest.raises(FrozenInstanceError):
        result.permit_id = "other"
    assert current.manual_review_permits[0].permit_id == "permit-A-journal_storage"
    assert package_item.provenance_kind == "manual_review_permit"
    assert verified_context.trust_policy_sha256 == current.policy_sha256


def test_missing_or_failed_provider_evidence_never_becomes_manual_review_authority():
    current = policy(permit())
    with pytest.raises(OperationalEvidenceError):
        verify(current, replace(item(current), provenance_kind="provider_result"))
