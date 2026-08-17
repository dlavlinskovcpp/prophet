import pytest
from solders.pubkey import Pubkey

from src.attester import AttesterService
from src.config import settings


def _service() -> AttesterService:
    return object.__new__(AttesterService)


def test_threshold_markets_are_allowed(monkeypatch):
    del monkeypatch
    svc = _service()

    svc._enforce_resolution_mode_policy({"notary_config": Pubkey.new_unique()})


def test_legacy_single_oracle_is_rejected(monkeypatch):
    del monkeypatch
    svc = _service()

    with pytest.raises(PermissionError):
        svc._enforce_resolution_mode_policy({"notary_config": Pubkey.default()})


def test_production_requires_secure_coordinator(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "RESOLUTION_MODE", "legacy-test")
    monkeypatch.setattr(settings, "GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED", False)
    with pytest.raises(ValueError, match="Production requires"):
        settings.validate_settlement_cutover_runtime()


def test_secure_mode_rejects_generic_remote_settlement_signer(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "RESOLUTION_MODE", "secure-coordinator")
    monkeypatch.setattr(settings, "GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED", True)
    with pytest.raises(ValueError, match="Generic remote settlement signing"):
        settings.validate_settlement_cutover_runtime()


def test_generic_remote_signer_service_cannot_start_in_secure_mode(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "RESOLUTION_MODE", "secure-coordinator")
    monkeypatch.setattr(settings, "GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED", False)
    with pytest.raises(ValueError, match="disabled in secure-coordinator"):
        settings.validate_remote_signer_service_runtime()
