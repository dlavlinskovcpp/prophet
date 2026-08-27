"""R5 active-authority package freshness and signed-deadline regressions."""
from __future__ import annotations

import hashlib
import runpy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from solders.keypair import Keypair

from src.operational_evidence import evidence_preimage
from src.r3c_effective_authority import derive_r3c_effective_authority


I4 = runpy.run_path(str(Path(__file__).with_name("test_r3c_effective_authority.py")))
NOW = datetime(2026, 8, 25, 12, 30, tzinfo=timezone.utc)


def _package(generated: str, valid_until: str) -> tuple[object, dict, dict, dict, object]:
    policy, inventory, providers, vaults, context = I4["fixture"]()
    package = I4["signed_package"](inventory, policy)
    unsigned = package["unsigned_package"]
    unsigned["generated_at"] = generated
    unsigned["valid_until"] = valid_until
    preimage = evidence_preimage(unsigned)
    digest = hashlib.sha256(preimage).hexdigest()
    for signature, seed in zip(package["signatures"], (1, 2)):
        signature["issued_at"] = generated
        signature["valid_until"] = valid_until
        signature["signed_payload_sha256"] = digest
        signature["signature_bytes"] = I4["b64"](bytes(Keypair.from_seed(bytes([seed]) * 32).sign_message(preimage)))
    return policy, package, providers, vaults, replace(context, package_valid_until=valid_until)


def _derive(parts, *, now=NOW, context=None):
    policy, package, providers, vaults, original_context = parts
    return derive_r3c_effective_authority(
        package, policy=policy, raw_provider_results=providers,
        raw_vault_admin_attestations=vaults, trusted_context=context or original_context,
        trusted_now=now,
    )


def _resign_package(package: dict) -> None:
    preimage = evidence_preimage(package["unsigned_package"])
    digest = hashlib.sha256(preimage).hexdigest()
    for signature, seed in zip(package["signatures"], (1, 2)):
        signature["signed_payload_sha256"] = digest
        signature["signature_bytes"] = I4["b64"](bytes(Keypair.from_seed(bytes([seed]) * 32).sign_message(preimage)))


@pytest.mark.parametrize("now", (datetime(2026, 8, 25, 12, 30, tzinfo=timezone.utc), datetime(2026, 8, 25, 12, 31, tzinfo=timezone.utc)))
def test_signed_package_expiry_rejects_despite_fresh_subordinate_evidence(now):
    with pytest.raises(ValueError):
        _derive(_package("2026-08-25T11:00:00Z", "2026-08-25T12:30:00Z"), now=now)


def test_signed_package_max_age_and_future_skew_reject():
    with pytest.raises(ValueError):
        _derive(_package("2026-08-24T12:00:00Z", "2026-08-26T12:00:00Z"))
    with pytest.raises(ValueError):
        _derive(_package("2026-08-25T12:36:00Z", "2026-08-25T13:00:00Z"))


def test_signed_package_exact_24_hour_age_boundary_accepts():
    assert _derive(_package("2026-08-24T12:30:00Z", "2026-08-25T13:00:00Z")).public_devnet_sufficient


def test_signed_package_generated_at_equal_valid_until_rejects():
    parts = _package("2026-08-25T12:35:00Z", "2026-08-25T13:00:00Z")
    parts[1]["unsigned_package"]["valid_until"] = "2026-08-25T12:35:00Z"
    _resign_package(parts[1])
    with pytest.raises(ValueError):
        _derive(parts, context=replace(parts[4], package_valid_until="2026-08-25T12:35:00Z"))


def test_signed_package_future_skew_boundary_and_max_interval_boundary_accept():
    assert _derive(_package("2026-08-25T12:35:00Z", "2026-08-28T12:35:00Z")).public_devnet_sufficient
    assert _derive(_package("2026-08-25T12:00:00Z", "2026-08-28T12:00:00Z")).public_devnet_sufficient


def test_signed_package_interval_over_72_hours_rejects():
    with pytest.raises(ValueError):
        _derive(_package("2026-08-25T12:00:00Z", "2026-08-28T12:00:01Z"))


@pytest.mark.parametrize("deadline", ("2026-08-25T13:01:00Z", "2026-08-25T12:59:00Z"))
def test_context_deadline_must_exactly_match_signed_package(deadline):
    parts = _package("2026-08-25T11:00:00Z", "2026-08-25T13:00:00Z")
    with pytest.raises(ValueError):
        _derive(parts, context=replace(parts[4], package_valid_until=deadline))


def test_expired_package_with_later_context_deadline_rejects_before_subordinate_use():
    parts = _package("2026-08-25T11:00:00Z", "2026-08-25T12:30:00Z")
    with pytest.raises(ValueError):
        _derive(parts, context=replace(parts[4], package_valid_until="2026-08-25T13:00:00Z"))


@pytest.mark.parametrize("field,value", (("environment", "other-env"), ("git_sha", "b" * 40), ("evidence_set_id", "other-evidence")))
def test_signed_package_release_context_must_match_trusted_context(field, value):
    parts = _package("2026-08-25T11:00:00Z", "2026-08-25T13:00:00Z")
    with pytest.raises(ValueError):
        _derive(parts, context=replace(parts[4], **{field: value}))


@pytest.mark.parametrize("role", ("deployment-operator", "security-reviewer"))
def test_required_signature_envelope_expiry_rejects(role):
    parts = _package("2026-08-25T11:00:00Z", "2026-08-25T13:00:00Z")
    signature = next(item for item in parts[1]["signatures"] if item["signer_type"] == role)
    signature["valid_until"] = "2026-08-25T12:30:00Z"
    with pytest.raises(ValueError):
        _derive(parts)


@pytest.mark.parametrize("role", ("deployment-operator", "security-reviewer"))
def test_required_signature_envelope_after_expiry_rejects(role):
    parts = _package("2026-08-25T11:00:00Z", "2026-08-25T13:00:00Z")
    signature = next(item for item in parts[1]["signatures"] if item["signer_type"] == role)
    signature["valid_until"] = "2026-08-25T12:29:59Z"
    with pytest.raises(ValueError):
        _derive(parts)


@pytest.mark.parametrize("role", ("deployment-operator", "security-reviewer"))
def test_required_signature_envelope_future_and_malformed_intervals_reject(role):
    for issued, until in (("2026-08-25T12:36:00Z", "2026-08-25T13:00:00Z"), ("2026-08-25T13:00:00Z", "2026-08-25T13:00:00Z")):
        parts = _package("2026-08-25T11:00:00Z", "2026-08-25T13:00:00Z")
        signature = next(item for item in parts[1]["signatures"] if item["signer_type"] == role)
        signature["issued_at"], signature["valid_until"] = issued, until
        with pytest.raises(ValueError):
            _derive(parts)


def test_expired_package_rejects_with_manual_review_alternative():
    policy, inventory, providers, vaults, context = I4["fixture"](manual=True)
    package = I4["signed_package"](inventory, policy)
    package["unsigned_package"]["valid_until"] = "2026-08-25T12:30:00Z"
    package["unsigned_package"]["generated_at"] = "2026-08-25T11:00:00Z"
    preimage = evidence_preimage(package["unsigned_package"])
    digest = hashlib.sha256(preimage).hexdigest()
    for signature, seed in zip(package["signatures"], (1, 2)):
        signature.update({"issued_at": "2026-08-25T11:00:00Z", "valid_until": "2026-08-25T12:30:00Z", "signed_payload_sha256": digest, "signature_bytes": I4["b64"](bytes(Keypair.from_seed(bytes([seed]) * 32).sign_message(preimage)))})
    with pytest.raises(ValueError):
        derive_r3c_effective_authority(package, policy=policy, raw_provider_results=providers, raw_vault_admin_attestations=vaults, trusted_context=replace(context, package_valid_until="2026-08-25T12:30:00Z"), trusted_now=NOW)
