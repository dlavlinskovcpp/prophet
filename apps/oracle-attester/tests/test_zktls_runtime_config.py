import pytest
from src.config import settings


def test_validate_zktls_runtime_requires_url(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "ALLOW_MOCK_ZKTLS", False)
    monkeypatch.setattr(settings, "ZKTLS_MODE", "reclaim_http")
    monkeypatch.setattr(settings, "REQUIRE_ZKTLS", True)
    monkeypatch.setattr(settings, "RECLAIM_VERIFY_URL", "")

    with pytest.raises(ValueError):
        settings.validate_zktls_runtime()


def test_validate_zktls_runtime_rejects_mock_in_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "ALLOW_MOCK_ZKTLS", False)
    monkeypatch.setattr(settings, "ZKTLS_MODE", "mock")

    with pytest.raises(ValueError):
        settings.validate_zktls_runtime()


def test_validate_zktls_runtime_allows_explicit_dev_mock(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "ALLOW_MOCK_ZKTLS", True)
    monkeypatch.setattr(settings, "ZKTLS_MODE", "mock")

    settings.validate_zktls_runtime()
