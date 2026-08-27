"""Deterministic, side-effect-free P0C3E1 verifier security tests."""
from __future__ import annotations

import base64
import copy
import hashlib
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import rfc8785
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature

from src.operational_evidence import (
    BASELINE_GIT_SHA,
    EVIDENCE_SIGNATURE_SCHEMA,
    EVIDENCE_DOMAIN,
    POLICY_SCHEMA,
    PROVIDER_ATTESTATION_SCHEMA,
    RESULT_SCHEMA,
    RESULT_SIGNATURE_SCHEMA,
    StaticSignerBinding,
    OperationalEvidenceError,
    evidence_preimage,
    parse_json_strict,
    result_preimage,
    _verify_legacy_operational_evidence_for_i5_vectors,
)


NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
_VECTOR_PATH = Path(__file__).with_name("vectors") / "operational_evidence_v1.fixture"


def _vector() -> dict:
    """Load only the immutable, independently generated cross-language vector."""
    value = parse_json_strict(_VECTOR_PATH.read_bytes())
    expected = {
        "schema", "version", "provenance", "trust_policy", "evidence",
        "provider_result", "evidence_set_id_mutation", "policy_version_mutation",
    }
    assert set(value) == expected
    assert value["schema"] == "PROPHET_OPERATIONAL_EVIDENCE_VECTOR_V1"
    assert value["version"] == 1
    return value


def _hex_object(value: dict, field: str = "jcs_hex") -> dict:
    return parse_json_strict(bytes.fromhex(value[field]))


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def h(byte: str) -> str:
    return byte * 64


def stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def policy(operator: Keypair, reviewer: Keypair, provider: Keypair) -> dict:
    key = lambda key_id, identity, kp: {"key_id": key_id, "identity": identity, "public_key": b64(bytes(kp.pubkey()))}
    return {
        "schema": POLICY_SCHEMA, "version": 1, "policy_id": "public-devnet-policy", "policy_version": 1,
        "environment": "public-devnet", "release_scope": [BASELINE_GIT_SHA],
        "allowed_algorithms": ["ed25519", "provider-native-v1"],
        "deployment_operator_keys": [key("operator-key", "operator-a", operator)],
        "security_reviewer_keys": [key("reviewer-key", "reviewer-a", reviewer)],
        "vault_admin_issuers": ["vault-admin-a"],
        "provider_issuer_policies": [{"issuer_identity": "provider-a", "provider_policy_ids": ["provider-policy-a"]}],
        "p0c3e2_verification_keys": [key("provider-result-key", "provider-result-a", provider)],
        "revoked_key_ids": [], "revoked_issuer_ids": [], "predecessor_policy_sha256": None,
    }


def bindings(a: Keypair, b: Keypair) -> tuple[StaticSignerBinding, StaticSignerBinding]:
    return (
        StaticSignerBinding("A", "signer-a", str(a.pubkey()), h("a"), h("c")),
        StaticSignerBinding("B", "signer-b", str(b.pubkey()), h("b"), h("d")),
    )


def signer(role: str, key: Keypair) -> dict:
    suffix = role.lower()
    return {
        "signer_role": role, "signer_id": f"signer-{suffix}", "signer_public_key": str(key.pubkey()),
        "host": f"host-{suffix}", "runtime_principal": f"runtime-{suffix}", "runtime_admin_domain": f"runtime-admin-{suffix}",
        "service_instance": f"service-{suffix}", "vault_auth_principal": f"vault-auth-{suffix}", "vault_admin_domain": f"vault-admin-{suffix}", "vault_tenant": f"vault-tenant-{suffix}",
        "rpc_credential_principal": f"rpc-credential-{suffix}", "rpc_provider": f"rpc-provider-{suffix}", "rpc_account": f"rpc-account-{suffix}",
        "journal_storage": f"journal-{suffix}", "audit_domain": f"audit-{suffix}", "tls_termination": f"tls-{suffix}",
    }


def artifact(role: str, generated: str, until: str) -> dict:
    suffix = role.lower()
    return {
        "artifact_id": f"artifact-{suffix}", "artifact_sha256": h("1" if role == "A" else "2"), "media_type": "application-json", "role": "infrastructure", "signer_role": role, "subject_account_scope": f"account-{suffix}",
        "evidence_set_id": "evidence-001", "environment": "public-devnet", "git_sha": BASELINE_GIT_SHA, "generated_at": generated, "valid_until": until,
        "raw_artifact_sha256": h("3" if role == "A" else "4"), "redacted_artifact_sha256": h("5" if role == "A" else "6"), "redaction_profile_version": "redaction-v1",
        "provider_issuer_identity": "provider-a", "provider_attestation_id": f"attestation-{suffix}", "provider_policy_id": "provider-policy-a",
    }


def unsigned(policy_value: dict, a: Keypair, b: Keypair, *, generated: datetime = NOW - timedelta(hours=1), until: datetime = NOW + timedelta(hours=1)) -> dict:
    generated_s, until_s = stamp(generated), stamp(until)
    return {
        "schema": "PROPHET_OPERATED_SIGNER_EVIDENCE_V1", "version": 1, "environment": "public-devnet", "git_sha": BASELINE_GIT_SHA,
        "trust_policy_id": policy_value["policy_id"], "trust_policy_version": 1, "trust_policy_sha256": hashlib.sha256(rfc8785.dumps(policy_value)).hexdigest(),
        "evidence_set_id": "evidence-001", "generated_at": generated_s, "valid_until": until_s,
        "service_config_fingerprints": {"A": h("a"), "B": h("b")}, "deployment_manifest_fingerprints": {"A": h("c"), "B": h("d")},
        "signers": [signer("A", a), signer("B", b)], "artifacts": [artifact("A", generated_s, until_s), artifact("B", generated_s, until_s)],
        "independence_assertions": {name: True for name in ("signer_public_key", "host", "runtime_principal", "runtime_admin_domain", "service_instance", "vault_auth_principal", "vault_admin_domain", "vault_tenant", "rpc_credential_principal", "rpc_provider", "rpc_account", "journal_storage", "audit_domain", "tls_termination")},
        "expected_evidence_classifications": {"host": "PROVIDER_ATTESTED", "runtime": "PROVIDER_ATTESTED", "vault": "VAULT_ADMIN_ATTESTED", "vault_key": "VAULT_ADMIN_ATTESTED", "rpc": "PROVIDER_ATTESTED", "journal": "PROVIDER_ATTESTED", "audit": "PROVIDER_ATTESTED", "tls": "PROVIDER_ATTESTED", "process": "MACHINE_VERIFIED"},
        "redaction_provenance": {},
    }


def reviewer_signature(role: str, identity: str, key_id: str, kp: Keypair, value: dict) -> dict:
    preimage = evidence_preimage(value)
    return {"signature_schema": EVIDENCE_SIGNATURE_SCHEMA, "signature_version": 1, "algorithm": "ed25519", "signer_type": role, "signer_identity": identity, "issuer_identity": identity, "key_id": key_id, "signed_payload_sha256": hashlib.sha256(preimage).hexdigest(), "signature_bytes": b64(bytes(kp.sign_message(preimage))), "issued_at": value["generated_at"], "valid_until": value["valid_until"]}


def provider_record(value: dict) -> dict:
    return {"signature_schema": PROVIDER_ATTESTATION_SCHEMA, "signature_version": 1, "algorithm": "provider-native-v1", "signer_type": "provider", "signer_identity": "provider-a", "issuer_identity": "provider-a", "provider_attestation_id": value["provider_attestation_id"], "provider_policy_id": value["provider_policy_id"], "attested_artifact_sha256": value["raw_artifact_sha256"], "issued_at": value["generated_at"], "valid_until": value["valid_until"]}


def provider_result(value: dict, key: Keypair) -> dict:
    unsigned_result = {"schema": RESULT_SCHEMA, "version": 1, "provider_attestation_id": value["provider_attestation_id"], "issuer_identity": "provider-a", "subject_account_scope": value["subject_account_scope"], "environment": "public-devnet", "git_sha": BASELINE_GIT_SHA, "evidence_set_id": "evidence-001", "signer_role": value["signer_role"], "raw_artifact_sha256": value["raw_artifact_sha256"], "redacted_artifact_sha256": value["redacted_artifact_sha256"], "provider_policy_id": "provider-policy-a", "verified_at": value["generated_at"], "valid_until": value["valid_until"], "result": "VERIFIED"}
    return {"unsigned_result": unsigned_result, "signature": {"signature_schema": RESULT_SIGNATURE_SCHEMA, "signature_version": 1, "algorithm": "ed25519", "key_id": "provider-result-key", "signature_bytes": b64(bytes(key.sign_message(result_preimage(unsigned_result))) )}}


def package_fixture(*, generated: datetime = NOW - timedelta(hours=1), until: datetime = NOW + timedelta(hours=1)):
    # TEST VECTOR ONLY: these deterministic seeds are never production material.
    operator, reviewer, provider, signer_a, signer_b = (Keypair.from_seed(bytes([value]) * 32) for value in range(1, 6))
    policy_value = policy(operator, reviewer, provider)
    unsigned_value = unsigned(policy_value, signer_a, signer_b, generated=generated, until=until)
    package = {"unsigned_package": unsigned_value, "signatures": [reviewer_signature("deployment-operator", "operator-a", "operator-key", operator, unsigned_value), reviewer_signature("security-reviewer", "reviewer-a", "reviewer-key", reviewer, unsigned_value)], "provider_attestations": [provider_record(item) for item in unsigned_value["artifacts"]]}
    results = [provider_result(item, provider) for item in unsigned_value["artifacts"]]
    return policy_value, package, bindings(signer_a, signer_b), results


def accept(policy_value, package, static, results):
    return _verify_legacy_operational_evidence_for_i5_vectors(package, authoritative_policy=policy_value, authorized_policy_digests={(policy_value["policy_id"], 1): hashlib.sha256(rfc8785.dumps(policy_value)).hexdigest()}, static_bindings=static, normalized_provider_results=results, now=NOW)


def resign_package(package: dict) -> None:
    """Re-sign a test-only package after a deliberate unsigned mutation."""
    # TEST VECTOR ONLY: deterministic seeds never represent production material.
    operator, reviewer = (Keypair.from_seed(bytes([value]) * 32) for value in (1, 2))
    unsigned_value = package["unsigned_package"]
    # Deliberately bypass validation so negative tests can attach otherwise-valid
    # signatures to malformed-but-canonical unsigned payloads.
    preimage = EVIDENCE_DOMAIN + struct.pack("<I", len(rfc8785.dumps(unsigned_value))) + rfc8785.dumps(unsigned_value)
    package["signatures"] = [
        {"signature_schema": EVIDENCE_SIGNATURE_SCHEMA, "signature_version": 1, "algorithm": "ed25519", "signer_type": "deployment-operator", "signer_identity": "operator-a", "issuer_identity": "operator-a", "key_id": "operator-key", "signed_payload_sha256": hashlib.sha256(preimage).hexdigest(), "signature_bytes": b64(bytes(operator.sign_message(preimage))), "issued_at": unsigned_value["generated_at"], "valid_until": unsigned_value["valid_until"]},
        {"signature_schema": EVIDENCE_SIGNATURE_SCHEMA, "signature_version": 1, "algorithm": "ed25519", "signer_type": "security-reviewer", "signer_identity": "reviewer-a", "issuer_identity": "reviewer-a", "key_id": "reviewer-key", "signed_payload_sha256": hashlib.sha256(preimage).hexdigest(), "signature_bytes": b64(bytes(reviewer.sign_message(preimage))), "issued_at": unsigned_value["generated_at"], "valid_until": unsigned_value["valid_until"]},
    ]
    assert Signature.from_bytes(base64.urlsafe_b64decode(package["signatures"][0]["signature_bytes"] + "==")).verify(operator.pubkey(), preimage)
    assert Signature.from_bytes(base64.urlsafe_b64decode(package["signatures"][1]["signature_bytes"] + "==")).verify(reviewer.pubkey(), preimage)


def provider_results_for(package: dict) -> list[dict]:
    # TEST VECTOR ONLY: this only produces valid P0C3E2 fixture signatures.
    provider = Keypair.from_seed(bytes([3]) * 32)
    return [provider_result(artifact_value, provider) for artifact_value in package["unsigned_package"]["artifacts"]]


def resign_provider_result(result: dict) -> None:
    """Re-sign a test-only normalized provider result after a temporal mutation."""
    provider = Keypair.from_seed(bytes([3]) * 32)
    result["signature"]["signature_bytes"] = b64(bytes(provider.sign_message(result_preimage(result["unsigned_result"]))))


def bind_package_to_policy(package: dict, policy_value: dict) -> None:
    package["unsigned_package"]["trust_policy_sha256"] = hashlib.sha256(rfc8785.dumps(policy_value)).hexdigest()
    resign_package(package)


def test_provider_result_temporal_positive_boundaries_accept():
    policy_value, package, static, results = package_fixture()
    for result in results:
        result["unsigned_result"]["verified_at"] = stamp(NOW + timedelta(minutes=5))
        resign_provider_result(result)
    accept(policy_value, package, static, results)

    policy_value, package, static, results = package_fixture()
    for result in results:
        result["unsigned_result"]["verified_at"] = stamp(NOW - timedelta(hours=24))
        resign_provider_result(result)
    accept(policy_value, package, static, results)

    policy_value, package, static, results = package_fixture(generated=NOW, until=NOW + timedelta(hours=72))
    for result in results:
        result["unsigned_result"]["verified_at"] = stamp(NOW)
        resign_provider_result(result)
    accept(policy_value, package, static, results)


@pytest.mark.parametrize("verified_at,valid_until", (
    (datetime(2000, 1, 1, tzinfo=timezone.utc), NOW + timedelta(hours=1)),
    (NOW + timedelta(minutes=5, seconds=1), NOW + timedelta(hours=1)),
    (NOW - timedelta(hours=24, seconds=1), NOW + timedelta(hours=1)),
    (NOW + timedelta(minutes=30), NOW + timedelta(minutes=30)),
    (NOW + timedelta(minutes=31), NOW + timedelta(minutes=30)),
    (NOW - timedelta(hours=1), NOW),
    (NOW - timedelta(hours=2), NOW - timedelta(hours=1)),
))
def test_provider_result_temporal_negative_matrix_rejects(verified_at, valid_until):
    policy_value, package, static, results = package_fixture()
    results = copy.deepcopy(results)
    results[0]["unsigned_result"]["verified_at"] = stamp(verified_at)
    results[0]["unsigned_result"]["valid_until"] = stamp(valid_until)
    resign_provider_result(results[0])
    with pytest.raises(OperationalEvidenceError, match="provider_result_time_invalid"):
        accept(policy_value, package, static, results)


def test_provider_result_interval_and_package_containment_reject_independently():
    policy_value, package, static, results = package_fixture(
        generated=NOW + timedelta(seconds=1), until=NOW + timedelta(hours=72, seconds=1),
    )
    results[0]["unsigned_result"]["verified_at"] = stamp(NOW)
    results[0]["unsigned_result"]["valid_until"] = stamp(NOW + timedelta(hours=72, seconds=1))
    resign_provider_result(results[0])
    with pytest.raises(OperationalEvidenceError, match="provider_result_time_invalid"):
        accept(policy_value, package, static, results)

    policy_value, package, static, results = package_fixture()
    results[0]["unsigned_result"]["valid_until"] = stamp(NOW + timedelta(hours=1, seconds=1))
    resign_provider_result(results[0])
    with pytest.raises(OperationalEvidenceError, match="provider_result_time_invalid"):
        accept(policy_value, package, static, results)


@pytest.mark.parametrize(("field", "value"), (
    ("verified_at", "2026-08-25T12:00:00+00:00"),
    ("valid_until", "2026-08-25T13:00:00+00:00"),
    ("verified_at", "2026-08-25T12:00:00"),
    ("valid_until", "2026-08-25T13:00:00"),
    ("verified_at", "2026-08-25T12:00:00.000Z"),
    ("valid_until", "2026-08-25T13:00:00.000Z"),
    ("verified_at", None),
    ("valid_until", None),
))
def test_provider_result_timestamps_require_frozen_utc_z_format(field, value):
    policy_value, package, static, results = package_fixture()
    results[0]["unsigned_result"][field] = value
    with pytest.raises(OperationalEvidenceError, match=f"{'verified_at' if field == 'verified_at' else 'result_valid_until'}_invalid"):
        accept(policy_value, package, static, results)


def test_complete_public_devnet_package_accepts_without_runtime_capabilities():
    policy_value, package, static, results = package_fixture()
    result = accept(policy_value, package, static, results)
    assert result.evidence_set_id == "evidence-001" and result.git_sha == BASELINE_GIT_SHA
    assert dict(result.independence_assertions)["host"] is True
    assert dict(result.classifications)["process"] == "MACHINE_VERIFIED"
    assert not hasattr(result, "client") and not hasattr(result, "journal")


def test_rejects_duplicate_a_artifact_roles_with_no_b_coverage():
    policy_value, package, static, _ = package_fixture()
    package = copy.deepcopy(package)
    package["unsigned_package"]["artifacts"][1]["signer_role"] = "A"
    resign_package(package)
    with pytest.raises(OperationalEvidenceError, match="artifact_binding_invalid"):
        accept(policy_value, package, static, provider_results_for(package))


def test_rejects_global_role_presence_when_signer_category_coverage_is_split():
    policy_value, package, static, results = package_fixture()
    package = copy.deepcopy(package)
    # A/B artifact labels remain present, but B's host-category value is A's.
    package["unsigned_package"]["signers"][1]["host"] = package["unsigned_package"]["signers"][0]["host"]
    resign_package(package)
    with pytest.raises(OperationalEvidenceError, match="independence_collision|static_binding_mismatch"):
        accept(policy_value, package, static, results)


@pytest.mark.parametrize("field", (
    "signer_public_key", "host", "runtime_principal", "runtime_admin_domain",
    "service_instance", "vault_auth_principal", "vault_admin_domain", "vault_tenant",
    "rpc_credential_principal", "rpc_provider", "rpc_account", "journal_storage",
    "audit_domain", "tls_termination",
))
def test_rejects_each_wrong_role_signer_evidence_category(field):
    policy_value, package, static, results = package_fixture()
    package = copy.deepcopy(package)
    package["unsigned_package"]["signers"][1][field] = package["unsigned_package"]["signers"][0][field]
    resign_package(package)
    with pytest.raises(OperationalEvidenceError, match="independence_collision|static_binding_mismatch"):
        accept(policy_value, package, static, results)


def test_rejects_provider_result_cross_role_reuse_and_unresigned_role_mutation():
    policy_value, package, static, results = package_fixture()
    with pytest.raises(OperationalEvidenceError, match="provider_result_binding_invalid"):
        accept(policy_value, package, static, [results[1], results[0]])
    with pytest.raises(OperationalEvidenceError, match="provider_result_role_coverage_invalid"):
        accept(policy_value, package, static, [results[0], results[0]])
    forged = copy.deepcopy(results)
    forged[0]["unsigned_result"]["signer_role"] = "B"
    resign_package(package)
    with pytest.raises(OperationalEvidenceError, match="provider_result_signature_invalid"):
        accept(policy_value, package, static, forged)


def test_rejects_shared_release_artifact_as_signer_specific_evidence():
    policy_value, package, static, _ = package_fixture()
    package = copy.deepcopy(package)
    package["unsigned_package"]["artifacts"][1]["role"] = "shared-release"
    resign_package(package)
    with pytest.raises(OperationalEvidenceError, match="artifact_binding_invalid"):
        accept(policy_value, package, static, provider_results_for(package))


@pytest.mark.parametrize("identity", ("artifact_id", "provider_attestation_id", "full_hash_identity"))
def test_rejects_reused_signer_specific_artifact_identity(identity):
    policy_value, package, static, _ = package_fixture()
    package = copy.deepcopy(package)
    if identity == "full_hash_identity":
        for field in ("artifact_sha256", "raw_artifact_sha256", "redacted_artifact_sha256"):
            package["unsigned_package"]["artifacts"][1][field] = package["unsigned_package"]["artifacts"][0][field]
    else:
        package["unsigned_package"]["artifacts"][1][identity] = package["unsigned_package"]["artifacts"][0][identity]
    resign_package(package)
    with pytest.raises(OperationalEvidenceError, match="artifact_binding_invalid"):
        accept(policy_value, package, static, provider_results_for(package))


def test_rejects_revoked_p0c3e2_verification_key():
    policy_value, package, static, results = package_fixture()
    policy_value, package = copy.deepcopy(policy_value), copy.deepcopy(package)
    policy_value["revoked_key_ids"] = ["provider-result-key"]
    bind_package_to_policy(package, policy_value)
    with pytest.raises(OperationalEvidenceError, match="provider_result_key_revoked"):
        accept(policy_value, package, static, results)


def test_rejects_revoked_reviewer_public_key_alias_before_signature_acceptance():
    policy_value, package, static, results = package_fixture()
    policy_value, package = copy.deepcopy(policy_value), copy.deepcopy(package)
    alias = copy.deepcopy(policy_value["deployment_operator_keys"][0])
    alias["key_id"] = "operator-key-alias"
    policy_value["deployment_operator_keys"].append(alias)
    policy_value["revoked_key_ids"] = ["operator-key"]
    bind_package_to_policy(package, policy_value)
    package["signatures"][0]["key_id"] = "operator-key-alias"
    with pytest.raises(OperationalEvidenceError, match="trust_policy_duplicate_public_key"):
        accept(policy_value, package, static, results)


@pytest.mark.parametrize("target", ("security_reviewer_keys", "p0c3e2_verification_keys"))
def test_rejects_operator_public_key_reused_across_trust_roles(target):
    policy_value, package, static, results = package_fixture()
    policy_value, package = copy.deepcopy(policy_value), copy.deepcopy(package)
    alias = copy.deepcopy(policy_value["deployment_operator_keys"][0])
    alias["key_id"] = f"{target}-alias"
    alias["identity"] = f"{target}-identity"
    policy_value[target].append(alias)
    bind_package_to_policy(package, policy_value)
    with pytest.raises(OperationalEvidenceError, match="trust_policy_duplicate_public_key"):
        accept(policy_value, package, static, results)


def test_rejects_reviewer_public_key_reused_as_p0c3e2_key_and_identity_collision():
    policy_value, package, static, results = package_fixture()
    policy_value, package = copy.deepcopy(policy_value), copy.deepcopy(package)
    alias = copy.deepcopy(policy_value["security_reviewer_keys"][0])
    alias["key_id"] = "p0c3e2-alias"
    alias["identity"] = "p0c3e2-identity"
    policy_value["p0c3e2_verification_keys"].append(alias)
    bind_package_to_policy(package, policy_value)
    with pytest.raises(OperationalEvidenceError, match="trust_policy_duplicate_public_key"):
        accept(policy_value, package, static, results)
    policy_value, package = package_fixture()[0:2]
    policy_value, package = copy.deepcopy(policy_value), copy.deepcopy(package)
    policy_value["security_reviewer_keys"][0]["identity"] = "operator-a"
    bind_package_to_policy(package, policy_value)
    with pytest.raises(OperationalEvidenceError, match="trust_policy_reviewer_identity_collision"):
        accept(policy_value, package, static, results)


def test_rejects_duplicate_trust_key_id_across_sets():
    policy_value, package, static, results = package_fixture()
    policy_value, package = copy.deepcopy(policy_value), copy.deepcopy(package)
    policy_value["p0c3e2_verification_keys"][0]["key_id"] = "operator-key"
    bind_package_to_policy(package, policy_value)
    with pytest.raises(OperationalEvidenceError, match="trust_policy_duplicate_key_id"):
        accept(policy_value, package, static, results)


def test_immutable_cross_language_jcs_preimage_and_ed25519_vectors_are_exact():
    """All expected bytes are fixture literals, generated outside this test path.

    Provenance is recorded in the fixture: Node.js canonicalize@4.0.0 and native
    Node.js Ed25519 produced the values, then rfc8785/solders were independently
    used only for this test's equality/verification checks.
    """
    vector = _vector()
    policy_vector = vector["trust_policy"]
    evidence_vector = vector["evidence"]
    result_vector = vector["provider_result"]
    mutation_vector = vector["evidence_set_id_mutation"]
    policy_mutation_vector = vector["policy_version_mutation"]

    policy_value = _hex_object(policy_vector)
    unsigned_value = _hex_object(evidence_vector)
    result_value = _hex_object(result_vector)
    mutated_unsigned = _hex_object(mutation_vector)
    mutated_policy = _hex_object(policy_mutation_vector)

    expected_policy = bytes.fromhex(policy_vector["jcs_hex"])
    expected_evidence = bytes.fromhex(evidence_vector["jcs_hex"])
    expected_preimage = bytes.fromhex(evidence_vector["preimage_hex"])
    expected_result = bytes.fromhex(result_vector["jcs_hex"])
    expected_result_preimage = bytes.fromhex(result_vector["preimage_hex"])
    expected_mutated_evidence = bytes.fromhex(mutation_vector["jcs_hex"])
    expected_mutated_preimage = bytes.fromhex(mutation_vector["preimage_hex"])
    expected_mutated_policy = bytes.fromhex(policy_mutation_vector["jcs_hex"])

    assert rfc8785.dumps(policy_value) == expected_policy
    assert hashlib.sha256(expected_policy).hexdigest() == policy_vector["sha256"]
    assert rfc8785.dumps(unsigned_value) == expected_evidence
    assert evidence_preimage(unsigned_value) == expected_preimage
    assert hashlib.sha256(expected_preimage).hexdigest() == evidence_vector["sha256"]
    assert rfc8785.dumps(result_value) == expected_result
    assert result_preimage(result_value) == expected_result_preimage
    assert hashlib.sha256(expected_result_preimage).hexdigest() == result_vector["sha256"]

    # Exact fixed public-key and signature bytes, not merely a verification result.
    for prefix in ("operator", "reviewer"):
        public_key = base64.urlsafe_b64decode(evidence_vector[f"{prefix}_public_key_b64url"] + "==")
        signature = base64.urlsafe_b64decode(evidence_vector[f"{prefix}_signature_b64url"] + "==")
        assert public_key.hex() == evidence_vector[f"{prefix}_public_key_hex"]
        assert signature.hex() == evidence_vector[f"{prefix}_signature_hex"]
        assert Signature.from_bytes(signature).verify(Pubkey.from_bytes(public_key), expected_preimage)
    provider_key = base64.urlsafe_b64decode(result_vector["public_key_b64url"] + "==")
    provider_signature = base64.urlsafe_b64decode(result_vector["signature_b64url"] + "==")
    assert provider_key.hex() == result_vector["public_key_hex"]
    assert provider_signature.hex() == result_vector["signature_hex"]
    assert Signature.from_bytes(provider_signature).verify(Pubkey.from_bytes(provider_key), expected_result_preimage)

    assert rfc8785.dumps(mutated_unsigned) == expected_mutated_evidence
    assert evidence_preimage(mutated_unsigned) == expected_mutated_preimage
    assert hashlib.sha256(expected_mutated_preimage).hexdigest() == mutation_vector["sha256"]
    assert expected_mutated_evidence != expected_evidence
    assert expected_mutated_preimage != expected_preimage
    for prefix in ("operator", "reviewer"):
        key = base64.urlsafe_b64decode(evidence_vector[f"{prefix}_public_key_b64url"] + "==")
        sig = base64.urlsafe_b64decode(evidence_vector[f"{prefix}_signature_b64url"] + "==")
        assert not Signature.from_bytes(sig).verify(Pubkey.from_bytes(key), expected_mutated_preimage)

    assert rfc8785.dumps(mutated_policy) == expected_mutated_policy
    assert hashlib.sha256(expected_mutated_policy).hexdigest() == policy_mutation_vector["sha256"]
    assert policy_mutation_vector["sha256"] != policy_vector["sha256"]
    runtime_policy, package, static, results = package_fixture()
    assert rfc8785.dumps(runtime_policy) == expected_policy
    assert rfc8785.dumps(package["unsigned_package"]) == expected_evidence
    assert evidence_preimage(package["unsigned_package"]) == expected_preimage
    assert package["signatures"][0]["signature_bytes"] == evidence_vector["operator_signature_b64url"]
    assert package["signatures"][1]["signature_bytes"] == evidence_vector["reviewer_signature_b64url"]
    assert rfc8785.dumps(results[0]["unsigned_result"]) == expected_result
    assert result_preimage(results[0]["unsigned_result"]) == expected_result_preimage
    assert results[0]["signature"]["signature_bytes"] == result_vector["signature_b64url"]
    with pytest.raises(OperationalEvidenceError):
        accept(mutated_policy, package, static, results)


@pytest.mark.parametrize("raw", ('{"x":1,"x":2}', '{"outer":{"x":1,"x":2}}'))
def test_raw_json_duplicate_keys_fail_closed(raw):
    with pytest.raises(OperationalEvidenceError, match="duplicate_json_key"):
        parse_json_strict(raw)


@pytest.mark.parametrize("mutation", (
    lambda p, q, r: p["unsigned_package"].__setitem__("unknown", "x"),
    lambda p, q, r: p["unsigned_package"].pop("evidence_set_id"),
    lambda p, q, r: p["unsigned_package"].__setitem__("version", 2),
    lambda p, q, r: p["unsigned_package"].__setitem__("git_sha", "0" * 40),
    lambda p, q, r: p["signatures"].__setitem__(1, p["signatures"][0]),
    lambda p, q, r: p["signatures"][0].__setitem__("signature_bytes", p["signatures"][0]["signature_bytes"] + "="),
    lambda p, q, r: p["unsigned_package"]["signers"][1].__setitem__("host", p["unsigned_package"]["signers"][0]["host"]),
    lambda p, q, r: p["unsigned_package"]["expected_evidence_classifications"].__setitem__("host", "OPERATOR_ATTESTED"),
    lambda p, q, r: p["provider_attestations"][0].__setitem__("provider_policy_id", "other"),
    lambda p, q, r: r[0]["unsigned_result"].__setitem__("signer_role", "B"),
))
def test_security_mutations_reject(mutation):
    policy_value, package, static, results = package_fixture()
    package, policy_value, results = copy.deepcopy(package), copy.deepcopy(policy_value), copy.deepcopy(results)
    mutation(package, policy_value, results)
    with pytest.raises(OperationalEvidenceError):
        accept(policy_value, package, static, results)


def test_policy_digest_revocation_and_freshness_reject():
    policy_value, package, static, results = package_fixture()
    wrong = copy.deepcopy(policy_value); wrong["policy_id"] = "other-policy"
    with pytest.raises(OperationalEvidenceError): accept(wrong, package, static, results)
    policy_value, package, static, results = package_fixture()
    policy_value["revoked_key_ids"] = ["operator-key"]
    package["unsigned_package"]["trust_policy_sha256"] = hashlib.sha256(rfc8785.dumps(policy_value)).hexdigest()
    with pytest.raises(OperationalEvidenceError): accept(policy_value, package, static, results)
    policy_value, package, static, results = package_fixture()
    package["unsigned_package"]["generated_at"] = stamp(NOW - timedelta(hours=25))
    with pytest.raises(OperationalEvidenceError): accept(policy_value, package, static, results)


def test_signature_over_digest_and_plain_provider_boolean_reject():
    policy_value, package, static, results = package_fixture()
    digest = bytes.fromhex(package["signatures"][0]["signed_payload_sha256"])
    forged_key = Keypair.from_seed(bytes([1]) * 32)
    package["signatures"][0]["signature_bytes"] = b64(bytes(forged_key.sign_message(digest)))
    with pytest.raises(OperationalEvidenceError): accept(policy_value, package, static, results)
    policy_value, package, static, _ = package_fixture()
    with pytest.raises(OperationalEvidenceError): accept(policy_value, package, static, [{"verified": True}])


@pytest.mark.parametrize("change", (
    lambda policy_value, package, results: package["signatures"][0].__setitem__("algorithm", "unknown"),
    lambda policy_value, package, results: package["signatures"][0].__setitem__("key_id", "unknown-key"),
    lambda policy_value, package, results: policy_value["revoked_issuer_ids"].append("provider-a"),
    lambda policy_value, package, results: results[0]["signature"].__setitem__("key_id", "unknown-key"),
    lambda policy_value, package, results: package["unsigned_package"].__setitem__("valid_until", stamp(NOW + timedelta(hours=73))),
    lambda policy_value, package, results: package["signatures"][0].__setitem__("valid_until", stamp(NOW + timedelta(hours=2))),
))
def test_policy_signature_and_time_boundaries_fail_closed(change):
    policy_value, package, static, results = package_fixture()
    policy_value, package, results = copy.deepcopy(policy_value), copy.deepcopy(package), copy.deepcopy(results)
    change(policy_value, package, results)
    with pytest.raises(OperationalEvidenceError):
        accept(policy_value, package, static, results)
