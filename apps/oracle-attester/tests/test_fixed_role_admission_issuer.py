"""Permanent role-local, one-shot admission-grant issuer boundaries."""
from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone

import pytest
from solders.keypair import Keypair

from src.fixed_role_admission_issuer import (
    FixedRoleAdmissionIssuerConfig,
    FixedRoleAdmissionIssuerError,
    _issue_fixed_role_admission_grant,
    validate_role_local_issuer_isolation,
)
from src.signer_a_admission_issuer_main import issue_signer_a_admission_grant
from src.signer_admission_grant import (
    AdmissionGrantContext,
    AdmissionIssuerKeyV1,
    StrictSignerAuthorizationRequestV1,
    verify_admission_grant,
)
from src.signer_b_admission_issuer_main import issue_signer_b_admission_grant
from tests.test_signer_authorization import fixture


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
RUN_ID = "b" * 32


def _key(role: str) -> Keypair:
    return Keypair.from_seed(bytes(range(32 if role == "A" else 64, 64 if role == "A" else 96)))


def _config(role: str, *, key: Keypair | None = None, **overrides):
    key = key or _key(role)
    value = {
        "signer_role": role,
        "signer_service_id": f"signer-{role.lower()}",
        "environment": "public-devnet",
        "git_sha": "a" * 40,
        "evidence_set_id": "evidence-001",
        "issuer_id": f"issuer-{role.lower()}",
        "key_id": f"key-{role.lower()}",
        "issuer_public_key": str(key.pubkey()),
        "issuer_private_key_env": f"ISSUER_{role}_PRIVATE_KEY",
        "ttl_seconds": 300,
        "excluded_public_keys": [str(_key("B" if role == "A" else "A").pubkey())],
    }
    value.update(overrides)
    return value


def _raw_request():
    request, *_ = fixture()
    return request, json.dumps(request, separators=(",", ":")).encode("utf-8")


def _issue(role: str, *, config=None, raw=None, key=None, run_id=RUN_ID):
    request, default_raw = _raw_request()
    key = key or _key(role)
    artifact = _issue_fixed_role_admission_grant(
        fixed_role=role, config_value=config or _config(role, key=key),
        raw_request=default_raw if raw is None else raw, acceptance_run_id=run_id,
        key_loader=lambda _: key, clock=lambda: NOW, token_hex=lambda _: ("a" if role == "A" else "b") * 32,
    )
    return request, json.loads(artifact)


def _verify(role: str, request, artifact):
    config = _config(role)
    context = AdmissionGrantContext(role, config["signer_service_id"], config["environment"], config["git_sha"], config["evidence_set_id"], RUN_ID)
    trusted = AdmissionIssuerKeyV1(config["key_id"], config["issuer_id"], role, config["issuer_public_key"], "2026-08-27T11:00:00Z", "2026-08-27T13:00:00Z")
    return verify_admission_grant(
        unsigned_grant=artifact["unsigned_grant"], signature_envelope=artifact["signature_envelope"],
        request=StrictSignerAuthorizationRequestV1.from_mapping(request), context=context,
        issuer_keys=[trusted], trusted_now=NOW,
    )


@pytest.mark.parametrize("role", ("A", "B"))
def test_role_fixed_issuer_generates_g1_compatible_artifact(role):
    request, artifact = _issue(role)
    verified = _verify(role, request, artifact)
    assert verified.signer_role == role
    assert artifact["unsigned_grant"]["grant_id"] == ("a" if role == "A" else "b") * 32


def test_a_and_b_issuer_identity_and_key_sources_are_distinct():
    a = FixedRoleAdmissionIssuerConfig.from_mapping(_config("A"))
    b = FixedRoleAdmissionIssuerConfig.from_mapping(_config("B"))
    validate_role_local_issuer_isolation(a, b)
    assert a.issuer_public_key != b.issuer_public_key


@pytest.mark.parametrize("fixed,configured", (("A", "B"), ("B", "A")))
def test_role_override_is_rejected_before_key_use(fixed, configured):
    with pytest.raises(FixedRoleAdmissionIssuerError, match="fixed_issuer_role_mismatch"):
        _issue_fixed_role_admission_grant(
            fixed_role=fixed, config_value=_config(configured), raw_request=_raw_request()[1],
            acceptance_run_id=RUN_ID, key_loader=lambda _: pytest.fail("key loader called"),
        )


@pytest.mark.parametrize("role", ("A", "B"))
def test_opposite_issuer_key_is_rejected(role):
    with pytest.raises(FixedRoleAdmissionIssuerError, match="issuer_key_binding_invalid"):
        _issue_fixed_role_admission_grant(
            fixed_role=role, config_value=_config(role), raw_request=_raw_request()[1],
            acceptance_run_id=RUN_ID, key_loader=lambda _: _key("B" if role == "A" else "A"),
            clock=lambda: NOW,
        )


@pytest.mark.parametrize("field,value", (
    ("signer_service_id", "other-signer"), ("environment", "mainnet"),
    ("git_sha", "c" * 40), ("evidence_set_id", "other-evidence"),
    ("issuer_id", "other-issuer"), ("key_id", "other-key"),
))
def test_trusted_context_is_config_owned_and_g1_rejects_changed_binding(field, value):
    request, artifact = _issue("A")
    artifact["unsigned_grant"][field] = value
    with pytest.raises(Exception):
        _verify("A", request, artifact)


def test_grant_binds_the_strict_request_not_caller_digest():
    request, artifact = _issue("A")
    changed = dict(request)
    changed["market"] = "11111111111111111111111111111111"
    with pytest.raises(Exception):
        _verify("A", changed, artifact)


@pytest.mark.parametrize("raw", (b"{", b'{"schema":"x","schema":"x"}'))
def test_malformed_or_duplicate_request_produces_no_artifact(raw):
    with pytest.raises(FixedRoleAdmissionIssuerError, match="issuer_request_invalid"):
        _issue_fixed_role_admission_grant(
            fixed_role="A", config_value=_config("A"), raw_request=raw,
            acceptance_run_id=RUN_ID, key_loader=lambda _: pytest.fail("key loader called"),
        )


@pytest.mark.parametrize("run_id", ("not-hex", "a" * 31, "A" * 32))
def test_invalid_controller_run_id_is_rejected_before_key_use(run_id):
    with pytest.raises(FixedRoleAdmissionIssuerError, match="acceptance_run_id_invalid"):
        _issue_fixed_role_admission_grant(
            fixed_role="A", config_value=_config("A"), raw_request=_raw_request()[1],
            acceptance_run_id=run_id, key_loader=lambda _: pytest.fail("key loader called"),
        )


def test_ttl_over_sixty_minutes_and_key_purpose_alias_reject():
    with pytest.raises(FixedRoleAdmissionIssuerError, match="issuer_ttl_invalid"):
        FixedRoleAdmissionIssuerConfig.from_mapping(_config("A", ttl_seconds=3601))
    a = _config("A"); a["excluded_public_keys"] = [a["issuer_public_key"]]
    with pytest.raises(FixedRoleAdmissionIssuerError, match="issuer_key_purpose_alias"):
        FixedRoleAdmissionIssuerConfig.from_mapping(a)


def test_missing_public_devnet_issuer_key_has_no_localtest_fallback(monkeypatch):
    monkeypatch.delenv("ISSUER_A_PRIVATE_KEY", raising=False)
    with pytest.raises(FixedRoleAdmissionIssuerError, match="issuer_private_key_missing"):
        issue_signer_a_admission_grant(_config("A"), _raw_request()[1], RUN_ID)


def test_public_entrypoints_expose_only_config_request_and_run_id():
    assert tuple(inspect.signature(issue_signer_a_admission_grant).parameters) == ("config_value", "raw_request", "acceptance_run_id")
    assert tuple(inspect.signature(issue_signer_b_admission_grant).parameters) == ("config_value", "raw_request", "acceptance_run_id")


def test_issuer_module_has_no_settlement_or_journal_capability_imports():
    import src.fixed_role_admission_issuer as issuer
    source = inspect.getsource(issuer)
    forbidden = ("IndependentSignerEngine", "ThresholdResolutionSigner", "IndependentSignerJournal", "vault", "subprocess")
    assert all(token not in source for token in forbidden)
