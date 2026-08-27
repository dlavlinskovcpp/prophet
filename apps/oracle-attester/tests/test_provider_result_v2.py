"""I2 provider-result v2 cryptographic provenance regressions."""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone

import pytest
from solders.keypair import Keypair

from src.operational_evidence import (
    RESULT_SIGNATURE_SCHEMA, RESULT_V2_SCHEMA, OperationalEvidenceError,
    ProviderResultVerificationKey, result_v2_preimage, verify_provider_result_v2,
)

NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)
CATEGORIES = {
    "host_vm": ("host_id",), "runtime_principal": ("runtime_principal_id",),
    "runtime_admin_domain": ("runtime_admin_domain_id",),
    "rpc_credential_principal": ("rpc_credential_principal_id",),
    "rpc_provider": ("rpc_provider_id",), "rpc_account_project": ("rpc_account_project_id",),
    "journal_storage": ("journal_storage_id",), "audit_domain": ("audit_domain_id",),
    "tls_ingress": ("tls_ingress_id",),
}


def b64(v): return base64.urlsafe_b64encode(v).decode().rstrip("=")
def stamp(v): return v.strftime("%Y-%m-%dT%H:%M:%SZ")
def h(c): return c * 64


def fixture(category="host_vm"):
    key = Keypair.from_seed(bytes([30]) * 32)
    subject = {CATEGORIES[category][0]: f"{category}-a"}
    unsigned = {"schema": RESULT_V2_SCHEMA, "version": 2, "provider_attestation_id": "attestation-a", "issuer_identity": "provider-a", "subject_account_scope": "scope-a", "environment": "public-devnet", "git_sha": "f" * 40, "evidence_set_id": "evidence-a", "signer_role": "A", "evidence_category": category, "artifact_id": "artifact-a", "raw_artifact_sha256": h("a"), "redacted_artifact_sha256": h("b"), "provider_policy_id": "provider-policy-a", "issued_at": stamp(NOW - timedelta(hours=1)), "verified_at": stamp(NOW - timedelta(hours=1)), "valid_until": stamp(NOW + timedelta(hours=1)), "result": "VERIFIED", "subject": subject}
    signed = {"unsigned_result": unsigned, "signature": {"signature_schema": RESULT_SIGNATURE_SCHEMA, "signature_version": 1, "algorithm": "ed25519", "key_id": "provider-key", "signature_bytes": b64(bytes(key.sign_message(result_v2_preimage(unsigned))) )}}
    keys = [ProviderResultVerificationKey("provider-key", "provider-a", b64(bytes(key.pubkey())), stamp(NOW - timedelta(days=1)), stamp(NOW + timedelta(days=1)), ("provider-policy-a",))]
    return signed, keys, subject


def verify(value, keys, subject, **extra):
    u = value["unsigned_result"]
    args = dict(keys=keys, revoked_key_ids=[], revoked_issuer_ids=[], expected_signer_role="A", expected_evidence_category=u["evidence_category"], expected_artifact_id="artifact-a", expected_raw_artifact_sha256=h("a"), expected_redacted_artifact_sha256=h("b"), expected_subject=subject, package_valid_until=stamp(NOW + timedelta(hours=1)), now=NOW)
    args.update(extra)
    return verify_provider_result_v2(value, **args)


@pytest.mark.parametrize("category", tuple(CATEGORIES))
def test_each_provider_category_is_signed_and_verifies(category):
    value, keys, subject = fixture(category)
    assert verify(value, keys, subject).evidence_category == category


@pytest.mark.parametrize("name,value", (("expected_signer_role", "B"), ("expected_evidence_category", "rpc_provider"), ("expected_artifact_id", "artifact-b"), ("expected_raw_artifact_sha256", h("c")), ("expected_redacted_artifact_sha256", h("d"))))
def test_expected_context_replay_rejects(name, value):
    signed, keys, subject = fixture()
    with pytest.raises(OperationalEvidenceError, match="provider_v2_expected_context_invalid"):
        verify(signed, keys, subject, **{name: value})


@pytest.mark.parametrize("category", ("vault_auth_principal", "vault_admin_domain", "vault_account_tenant", "vault_key_identity_version", "worker_reload_concurrency"))
def test_provider_forbidden_categories_reject(category):
    signed, keys, subject = fixture()
    signed = copy.deepcopy(signed); signed["unsigned_result"]["evidence_category"] = category
    with pytest.raises(OperationalEvidenceError, match="provider_v2_category_forbidden"):
        verify(signed, keys, subject)


def test_schema_subject_key_crypto_and_temporal_fail_closed():
    signed, keys, subject = fixture()
    for mutate in (lambda x: x["unsigned_result"].__setitem__("version", 1), lambda x: x["unsigned_result"].__setitem__("unknown", True), lambda x: x["unsigned_result"].pop("artifact_id"), lambda x: x["unsigned_result"].__setitem__("signer_role", "a"), lambda x: x["unsigned_result"]["subject"].__setitem__("extra", "x"), lambda x: x["unsigned_result"].__setitem__("verified_at", stamp(NOW - timedelta(hours=25))), lambda x: x["unsigned_result"].__setitem__("valid_until", stamp(NOW + timedelta(hours=73)))):
        value = copy.deepcopy(signed); mutate(value)
        with pytest.raises(OperationalEvidenceError): verify(value, keys, subject)
    with pytest.raises(OperationalEvidenceError): verify(signed, [], subject)
    with pytest.raises(OperationalEvidenceError): verify(signed, keys, subject, revoked_key_ids=["provider-key"])
    with pytest.raises(OperationalEvidenceError): verify(signed, keys, subject, revoked_issuer_ids=["provider-a"])


def test_wrong_signature_subject_and_key_validity_reject():
    signed, keys, subject = fixture()
    value = copy.deepcopy(signed); value["signature"]["signature_bytes"] = b64(bytes(64))
    with pytest.raises(OperationalEvidenceError): verify(value, keys, subject)
    with pytest.raises(OperationalEvidenceError): verify(signed, keys, {"host_id": "other"})
    short = ProviderResultVerificationKey("provider-key", "provider-a", keys[0].public_key, keys[0].valid_from, stamp(NOW), ("provider-policy-a",))
    with pytest.raises(OperationalEvidenceError, match="provider_v2_time_invalid"): verify(signed, [short], subject)
