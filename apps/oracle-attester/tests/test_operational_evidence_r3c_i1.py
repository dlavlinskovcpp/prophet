"""I1 strict R3C role/category and typed trust-policy parser regressions."""
from __future__ import annotations

import base64
import copy
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from solders.keypair import Keypair

from src.operational_evidence import (
    BASELINE_GIT_SHA,
    R3C_POLICY_SCHEMA,
    OperationalEvidenceError,
    parse_authorization_evidence_inventory,
    parse_authorization_evidence_item,
    parse_evidence_category,
    parse_r3c_trust_policy,
    parse_signer_role,
)


NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)
CATEGORIES = (
    "host_vm", "runtime_principal", "runtime_admin_domain",
    "vault_auth_principal", "vault_admin_domain", "vault_account_tenant",
    "vault_key_identity_version", "rpc_credential_principal", "rpc_provider",
    "rpc_account_project", "journal_storage", "audit_domain", "tls_ingress",
    "worker_reload_concurrency",
)


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def item(role: str, category: str) -> dict:
    return {
        "signer_role": role,
        "evidence_category": category,
        "artifact_id": f"artifact-{role}-{category}",
        "raw_artifact_sha256": digest(f"raw-{role}-{category}"),
        "redacted_artifact_sha256": digest(f"redacted-{role}-{category}"),
        "provenance_kind": "provider_result",
        "provenance_ref": f"provider-{role}-{category}",
    }


def inventory() -> list[dict]:
    return [item(role, category) for role in ("A", "B") for category in CATEGORIES]


def stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def key(seed: int, key_id: str, identity: str) -> dict:
    return {"key_id": key_id, "identity": identity, "public_key": b64(bytes(Keypair.from_seed(bytes([seed]) * 32).pubkey()))}


def policy() -> dict:
    return {
        "schema": R3C_POLICY_SCHEMA,
        "version": 2,
        "policy_id": "r3c-public-devnet-policy",
        "policy_version": 2,
        "environment": "public-devnet",
        "release_scope": [BASELINE_GIT_SHA],
        "allowed_algorithms": ["ed25519", "provider-native-v1"],
        "deployment_operator_keys": [key(1, "operator-key", "operator-a")],
        "security_reviewer_keys": [key(2, "reviewer-key", "reviewer-a")],
        "p0c3e2_verification_keys": [key(3, "p0c3e2-key", "p0c3e2-a")],
        "vault_admin_issuers": ["vault-admin-issuer-a"],
        "manual_review_permits": [],
        "vault_admin_verification_keys": [{
            "key_id": "vault-admin-key",
            "issuer_id": "vault-admin-issuer-a",
            "vault_admin_identity": "vault-admin-a",
            "public_key": b64(bytes(Keypair.from_seed(bytes([4]) * 32).pubkey())),
            "valid_from": stamp(NOW - timedelta(hours=1)),
            "valid_until": stamp(NOW + timedelta(hours=1)),
        }],
        "provider_issuer_policies": [{"issuer_identity": "provider-a", "provider_policy_ids": ["provider-policy-a"]}],
        "revoked_key_ids": [],
        "revoked_issuer_ids": [],
        "predecessor_policy_sha256": None,
    }


@pytest.mark.parametrize("value", ("unknown", "a", " A", "A ", 0, 1, True, False, None))
def test_strict_signer_role_rejects_noncanonical_values(value):
    with pytest.raises(OperationalEvidenceError, match="r3c_signer_role_invalid"):
        parse_signer_role(value)


@pytest.mark.parametrize("value", ("unknown", "HOST_VM", " host_vm", "host_vm ", 0, 1, True, False, None))
def test_strict_evidence_category_rejects_noncanonical_values(value):
    with pytest.raises(OperationalEvidenceError, match="r3c_evidence_category_invalid"):
        parse_evidence_category(value)


@pytest.mark.parametrize("mutation", (
    lambda value: value.__setitem__("extra", "x"),
    lambda value: value.pop("provenance_ref"),
    lambda value: value.__setitem__("raw_artifact_sha256", "A" * 64),
    lambda value: value.__setitem__("artifact_id", ""),
    lambda value: value.__setitem__("provenance_ref", ""),
    lambda value: value.__setitem__("provenance_kind", "package_label"),
))
def test_evidence_item_shape_and_values_fail_closed(mutation):
    value = item("A", "host_vm")
    mutation(value)
    with pytest.raises(OperationalEvidenceError):
        parse_authorization_evidence_item(value)


def test_exact_role_category_inventory_accepts():
    parsed = parse_authorization_evidence_inventory(inventory())
    assert len(parsed) == 28


@pytest.mark.parametrize("mutation", (
    lambda values: values.pop(),
    lambda values: values.append(copy.deepcopy(values[0])),
    lambda values: values.__setitem__(1, copy.deepcopy(values[0])),
    lambda values: values[1].__setitem__("artifact_id", values[0]["artifact_id"]),
    lambda values: values[1].update({"artifact_id": values[0]["artifact_id"], "raw_artifact_sha256": values[0]["raw_artifact_sha256"], "redacted_artifact_sha256": values[0]["redacted_artifact_sha256"]}),
    lambda values: values[14].__setitem__("artifact_id", values[0]["artifact_id"]),
    lambda values: values[1].__setitem__("artifact_id", values[0]["artifact_id"]),
))
def test_inventory_rejects_size_pair_and_artifact_reuse(mutation):
    values = inventory()
    mutation(values)
    with pytest.raises(OperationalEvidenceError):
        parse_authorization_evidence_inventory(values)


@pytest.mark.parametrize("mutation", (
    lambda value: value.pop("vault_admin_verification_keys"),
    lambda value: value.__setitem__("unexpected", True),
    lambda value: value["vault_admin_verification_keys"][0].__setitem__("public_key", "not-base64"),
    lambda value: value["vault_admin_verification_keys"][0].__setitem__("public_key", b64(bytes(31))),
    lambda value: value["vault_admin_verification_keys"][0].update({"valid_from": stamp(NOW), "valid_until": stamp(NOW)}),
))
def test_vault_admin_policy_record_is_strict(mutation):
    value = policy()
    mutation(value)
    with pytest.raises(OperationalEvidenceError):
        parse_r3c_trust_policy(value)


@pytest.mark.parametrize("family", ("deployment_operator_keys", "security_reviewer_keys", "p0c3e2_verification_keys"))
def test_policy_rejects_vault_admin_key_id_collision_with_each_family(family):
    value = policy()
    value[family][0]["key_id"] = "vault-admin-key"
    with pytest.raises(OperationalEvidenceError, match="r3c_trust_policy_duplicate_key_id"):
        parse_r3c_trust_policy(value)


@pytest.mark.parametrize("family", ("deployment_operator_keys", "security_reviewer_keys", "p0c3e2_verification_keys"))
def test_policy_rejects_decoded_vault_admin_public_key_collision_with_each_family(family):
    value = policy()
    value[family][0]["public_key"] = value["vault_admin_verification_keys"][0]["public_key"]
    with pytest.raises(OperationalEvidenceError, match="r3c_trust_policy_duplicate_public_key"):
        parse_r3c_trust_policy(value)


def test_policy_rejects_revoked_vault_admin_key_and_issuer():
    value = policy()
    value["revoked_key_ids"] = ["vault-admin-key"]
    with pytest.raises(OperationalEvidenceError, match="r3c_trust_policy_revoked_key"):
        parse_r3c_trust_policy(value)
    value = policy()
    value["revoked_issuer_ids"] = ["vault-admin-issuer-a"]
    with pytest.raises(OperationalEvidenceError, match="r3c_trust_policy_revoked_key"):
        parse_r3c_trust_policy(value)


def test_vault_admin_issuer_allowlist_without_a_pinned_key_rejects():
    value = policy()
    value["vault_admin_verification_keys"] = []
    with pytest.raises(OperationalEvidenceError, match="r3c_vault_admin_keys_invalid"):
        parse_r3c_trust_policy(value)


def test_four_key_families_pairwise_disjoint_accept_and_issuer_is_not_a_key():
    parsed = parse_r3c_trust_policy(policy())
    assert len(parsed.vault_admin_verification_keys) == 1
    assert parsed.vault_admin_issuers == ("vault-admin-issuer-a",)
