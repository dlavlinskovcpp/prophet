"""D2 pure Vault-admin attestation primitive regressions."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
import rfc8785

from src.vault_admin_attestation import (
    ATTESTATION_SCHEMA, SIGNATURE_SCHEMA, AuthoritativeEd25519Key, TrustedVaultSubject,
    VaultAdminAttestationError, VaultAdminVerificationKey, attestation_preimage,
    verify_vault_admin_attestation,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
SHA = "a" * 64
VECTOR = Path(__file__).with_name("vectors") / "vault_admin_attestation_v1.json"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def fixture(category="vault_auth_principal"):
    key = Keypair.from_seed(bytes([9]) * 32)
    subjects = {
        "vault_auth_principal": {"vault_auth_principal_id": "vault-auth-a"},
        "vault_admin_domain": {"vault_admin_domain_id": "vault-admin-a"},
        "vault_account_tenant": {"vault_account_or_tenant_id": "vault-tenant-a"},
        "vault_key_identity_version": {"vault_key_name": "vault-key-a", "signer_key_version": 1, "signer_public_key": str(Keypair.from_seed(bytes([7]) * 32).pubkey())},
    }
    trusted = TrustedVaultSubject("vault-auth-a", "vault-admin-a", "vault-tenant-a", "vault-key-a", 1, str(Keypair.from_seed(bytes([7]) * 32).pubkey()))
    unsigned = {"schema": ATTESTATION_SCHEMA, "version": 1, "environment": "public-devnet", "git_sha": "f" * 40, "evidence_set_id": "evidence-001", "signer_role": "A", "evidence_category": category, "artifact_id": "artifact-a", "raw_artifact_sha256": SHA, "redacted_artifact_sha256": "b" * 64, "issuer_id": "vault-issuer-a", "vault_admin_identity": "vault-admin-a", "key_id": "vault-key-id", "subject": subjects[category], "issued_at": stamp(NOW - timedelta(hours=1)), "valid_until": stamp(NOW + timedelta(hours=1))}
    preimage = attestation_preimage(unsigned)
    value = {"unsigned_attestation": unsigned, "signature": {"schema": SIGNATURE_SCHEMA, "version": 1, "algorithm": "ed25519", "signer_type": "vault-admin", "issuer_id": "vault-issuer-a", "vault_admin_identity": "vault-admin-a", "key_id": "vault-key-id", "signed_payload_sha256": hashlib.sha256(preimage).hexdigest(), "signature": b64(bytes(key.sign_message(preimage))), "issued_at": unsigned["issued_at"], "valid_until": unsigned["valid_until"]}}
    keys = [VaultAdminVerificationKey("vault-key-id", "vault-issuer-a", "vault-admin-a", b64(bytes(key.pubkey())), stamp(NOW - timedelta(days=1)), stamp(NOW + timedelta(days=1)))]
    return value, keys, trusted


def verify(value, keys, trusted, **extra):
    def trust(seed, role): return [AuthoritativeEd25519Key(f"{role}-key", b64(bytes(Keypair.from_seed(bytes([seed]) * 32).pubkey())))]
    args = {"keys": keys, "deployment_operator_keys": trust(10, "operator"), "security_reviewer_keys": trust(11, "reviewer"), "p0c3e2_verification_keys": trust(12, "p0c3e2"), "vault_admin_issuers": ["vault-issuer-a"], "revoked_key_ids": [], "revoked_issuer_ids": [], "trusted_subject": trusted, "expected_environment": "public-devnet", "expected_git_sha": "f" * 40, "expected_evidence_set_id": "evidence-001", "expected_signer_role": "A", "expected_evidence_category": value["unsigned_attestation"]["evidence_category"], "expected_artifact_id": "artifact-a", "expected_raw_artifact_sha256": SHA, "expected_redacted_artifact_sha256": "b" * 64, "package_valid_until": stamp(NOW + timedelta(hours=1)), "now": NOW}
    args.update(extra)
    return verify_vault_admin_attestation(value, **args)


def resign(value):
    """TEST ONLY: re-sign one otherwise-valid mutation with the fixed vector key."""
    key = Keypair.from_seed(bytes([9]) * 32)
    preimage = attestation_preimage(value["unsigned_attestation"])
    value["signature"]["signed_payload_sha256"] = hashlib.sha256(preimage).hexdigest()
    value["signature"]["signature"] = b64(bytes(key.sign_message(preimage)))


def set_times(value, issued, until):
    value["unsigned_attestation"]["issued_at"] = stamp(issued)
    value["unsigned_attestation"]["valid_until"] = stamp(until)
    value["signature"]["issued_at"] = stamp(issued)
    value["signature"]["valid_until"] = stamp(until)
    resign(value)


@pytest.mark.parametrize("category", ("vault_auth_principal", "vault_admin_domain", "vault_account_tenant", "vault_key_identity_version"))
def test_each_legal_category_requires_a_valid_category_bound_signature(category):
    value, keys, trusted = fixture(category)
    assert verify(value, keys, trusted).evidence_category == category


@pytest.mark.parametrize("field,value", (("signer_role", "B"), ("evidence_category", "vault_admin_domain"), ("artifact_id", "artifact-b"), ("evidence_set_id", "other")))
def test_signed_context_mutations_reject(field, value):
    signed, keys, trusted = fixture()
    signed = copy.deepcopy(signed); signed["unsigned_attestation"][field] = value
    with pytest.raises(VaultAdminAttestationError): verify(signed, keys, trusted)


def test_revocation_alias_and_signature_over_digest_reject():
    signed, keys, trusted = fixture()
    with pytest.raises(VaultAdminAttestationError): verify(signed, keys, trusted, revoked_key_ids=["vault-key-id"])
    alias = VaultAdminVerificationKey("alias", "vault-issuer-a", "vault-admin-a", keys[0].public_key, keys[0].valid_from, keys[0].valid_until)
    with pytest.raises(VaultAdminAttestationError): verify(signed, [keys[0], alias], trusted)
    signed = copy.deepcopy(signed)
    digest = bytes.fromhex(signed["signature"]["signed_payload_sha256"])
    key = Keypair.from_seed(bytes([9]) * 32)
    signed["signature"]["signature"] = b64(bytes(key.sign_message(digest)))
    with pytest.raises(VaultAdminAttestationError, match="vault_admin_signature_invalid"): verify(signed, keys, trusted)


def test_immutable_independently_generated_vault_admin_vector_is_byte_exact():
    """Expected constants are Node v20.19.6 crypto/JCS literals from the fixture."""
    vector = json.loads(VECTOR.read_text())
    primary = vector["unsigned_attestation"]
    expected_jcs = bytes.fromhex(vector["jcs_hex"])
    expected_preimage = bytes.fromhex(vector["preimage_hex"])
    assert rfc8785.dumps(primary) == expected_jcs
    assert b"PROPHET_VAULT_ADMIN_ATTESTATION_V1\0" + struct.pack("<I", len(expected_jcs)) + expected_jcs == expected_preimage
    assert attestation_preimage(primary) == expected_preimage
    assert hashlib.sha256(expected_preimage).hexdigest() == vector["preimage_sha256"]
    public = bytes.fromhex(vector["public_key_hex"])
    signature = bytes.fromhex(vector["signature_hex"])
    assert public == base64.urlsafe_b64decode(vector["public_key_base64url"] + "==") and len(public) == 32
    assert signature == base64.urlsafe_b64decode(vector["signature_base64url"] + "==") and len(signature) == 64
    assert vector["signature_envelope"]["signed_payload_sha256"] == vector["preimage_sha256"]
    assert vector["signature_envelope"]["signature"] == vector["signature_base64url"]
    assert Signature.from_bytes(signature).verify(Pubkey.from_bytes(public), expected_preimage)
    for mutation in vector["mutations"].values():
        mutated_jcs, mutated_preimage = bytes.fromhex(mutation["jcs_hex"]), bytes.fromhex(mutation["preimage_hex"])
        assert rfc8785.dumps(mutation["unsigned_attestation"]) == mutated_jcs
        assert b"PROPHET_VAULT_ADMIN_ATTESTATION_V1\0" + struct.pack("<I", len(mutated_jcs)) + mutated_jcs == mutated_preimage
        assert hashlib.sha256(mutated_preimage).hexdigest() == mutation["preimage_sha256"]
        assert mutated_preimage != expected_preimage
        assert not Signature.from_bytes(signature).verify(Pubkey.from_bytes(public), mutated_preimage)


@pytest.mark.parametrize("issued,until,accepted", (
    (NOW + timedelta(minutes=5), NOW + timedelta(hours=1), True),
    (NOW + timedelta(minutes=5, seconds=1), NOW + timedelta(hours=1), False),
    (NOW - timedelta(hours=24, seconds=1), NOW + timedelta(hours=1), False),
    (NOW - timedelta(hours=1), NOW, False),
    (NOW - timedelta(hours=2), NOW - timedelta(hours=1), False),
    (NOW, NOW, False), (NOW + timedelta(minutes=1), NOW, False),
))
def test_temporal_adversarial_boundaries(issued, until, accepted):
    value, keys, trusted = fixture(); value = copy.deepcopy(value); set_times(value, issued, until)
    if accepted: verify(value, keys, trusted)
    else:
        with pytest.raises(VaultAdminAttestationError, match="vault_admin_time_invalid"): verify(value, keys, trusted)


def test_validity_and_key_containment_adversarial_boundaries():
    value, keys, trusted = fixture(); value = copy.deepcopy(value)
    set_times(value, NOW, NOW + timedelta(hours=72))
    value["signature"]["valid_until"] = stamp(NOW + timedelta(hours=1))
    keys = [VaultAdminVerificationKey(keys[0].key_id, keys[0].issuer_id, keys[0].vault_admin_identity, keys[0].public_key, stamp(NOW), stamp(NOW + timedelta(hours=72)))]
    verify(value, keys, trusted, package_valid_until=stamp(NOW + timedelta(hours=72)))
    bad = VaultAdminVerificationKey(keys[0].key_id, keys[0].issuer_id, keys[0].vault_admin_identity, keys[0].public_key, stamp(NOW + timedelta(seconds=1)), keys[0].valid_until)
    with pytest.raises(VaultAdminAttestationError, match="vault_admin_time_invalid"): verify(value, [bad], trusted, package_valid_until=stamp(NOW + timedelta(hours=72)))
    short = VaultAdminVerificationKey(keys[0].key_id, keys[0].issuer_id, keys[0].vault_admin_identity, keys[0].public_key, keys[0].valid_from, stamp(NOW + timedelta(hours=71)))
    with pytest.raises(VaultAdminAttestationError, match="vault_admin_time_invalid"): verify(value, [short], trusted, package_valid_until=stamp(NOW + timedelta(hours=72)))
    value, keys, trusted = fixture(); value = copy.deepcopy(value); set_times(value, NOW, NOW + timedelta(hours=72, seconds=1))
    key = VaultAdminVerificationKey(keys[0].key_id, keys[0].issuer_id, keys[0].vault_admin_identity, keys[0].public_key, stamp(NOW), stamp(NOW + timedelta(days=4)))
    with pytest.raises(VaultAdminAttestationError, match="vault_admin_time_invalid"): verify(value, [key], trusted, package_valid_until=stamp(NOW + timedelta(hours=72, seconds=1)))


def test_revoked_issuer_and_independent_context_reject():
    value, keys, trusted = fixture()
    with pytest.raises(VaultAdminAttestationError): verify(value, keys, trusted, revoked_issuer_ids=["vault-issuer-a"])
    for field, replacement in (("expected_environment", "other-env"), ("expected_git_sha", "e" * 40), ("expected_evidence_set_id", "other-evidence")):
        with pytest.raises(VaultAdminAttestationError, match="vault_admin_context_binding_invalid"): verify(value, keys, trusted, **{field: replacement})


def _assert_explicit_cross_role_key_reuse_rejects(role):
    """Each named authority has a distinct record but the same decoded key."""
    value, keys, trusted = fixture()
    other_role_key = base64.urlsafe_b64decode(keys[0].public_key + "==")
    assert len(other_role_key) == 32
    named = {"deployment-operator": "deployment_operator_keys", "security-reviewer": "security_reviewer_keys", "p0c3e2-verifier": "p0c3e2_verification_keys"}[role]
    with pytest.raises(VaultAdminAttestationError, match="vault_admin_duplicate_public_key"):
        verify(value, keys, trusted, **{named: [AuthoritativeEd25519Key(f"{role}-collision", b64(other_role_key))]})


def test_rejects_vault_admin_key_reused_by_deployment_operator():
    _assert_explicit_cross_role_key_reuse_rejects("deployment-operator")


def test_rejects_vault_admin_key_reused_by_security_reviewer():
    _assert_explicit_cross_role_key_reuse_rejects("security-reviewer")


def test_rejects_vault_admin_key_reused_by_p0c3e2_verifier():
    _assert_explicit_cross_role_key_reuse_rejects("p0c3e2-verifier")


@pytest.mark.parametrize("category,field,value", (
    ("vault_auth_principal", "vault_auth_principal_id", "other-auth"),
    ("vault_admin_domain", "vault_admin_domain_id", "other-domain"),
    ("vault_account_tenant", "vault_account_or_tenant_id", "other-tenant"),
    ("vault_key_identity_version", "vault_key_name", "other-key"),
    ("vault_key_identity_version", "signer_key_version", 2),
    ("vault_key_identity_version", "signer_public_key", str(Keypair.from_seed(bytes([8]) * 32).pubkey())),
))
def test_each_trusted_subject_field_is_independent(category, field, value):
    signed, keys, trusted = fixture(category); signed = copy.deepcopy(signed)
    signed["unsigned_attestation"]["subject"][field] = value; resign(signed)
    with pytest.raises(VaultAdminAttestationError, match="vault_admin_subject_binding_invalid"): verify(signed, keys, trusted)


def _role_key(seed, key_id):
    return AuthoritativeEd25519Key(key_id, b64(bytes(Keypair.from_seed(bytes([seed]) * 32).pubkey())))


@pytest.mark.parametrize("named", ("deployment_operator_keys", "security_reviewer_keys", "p0c3e2_verification_keys"))
def test_later_key_collision_is_scanned_for_each_named_authority(named):
    value, keys, trusted = fixture()
    named_keys = [_role_key(20, f"{named}-one"), _role_key(21, f"{named}-two"), AuthoritativeEd25519Key(f"{named}-collision", keys[0].public_key)]
    with pytest.raises(VaultAdminAttestationError, match="vault_admin_duplicate_public_key"):
        verify(value, keys, trusted, **{named: named_keys})


def test_four_role_disjoint_multi_key_sets_accept():
    value, keys, trusted = fixture()
    verify(value, keys, trusted,
        deployment_operator_keys=[_role_key(20, "operator-one"), _role_key(21, "operator-two")],
        security_reviewer_keys=[_role_key(22, "reviewer-one"), _role_key(23, "reviewer-two")],
        p0c3e2_verification_keys=[_role_key(24, "p0c3e2-one"), _role_key(25, "p0c3e2-two")])


def test_all_named_cross_role_inputs_are_required_keyword_only():
    signature = inspect.signature(verify_vault_admin_attestation)
    for name in ("deployment_operator_keys", "security_reviewer_keys", "p0c3e2_verification_keys"):
        parameter = signature.parameters[name]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty
