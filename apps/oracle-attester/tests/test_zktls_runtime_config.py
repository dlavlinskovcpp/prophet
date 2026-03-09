import pytest
from src.config import settings


def test_validate_zktls_runtime_requires_url(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "ZKTLS_MODE", "reclaim_http")
    monkeypatch.setattr(settings, "REQUIRE_ZKTLS", True)
    monkeypatch.setattr(settings, "RECLAIM_VERIFY_URL", "")

    with pytest.raises(ValueError):
        settings.validate_zktls_runtime()


def test_validate_zktls_runtime_rejects_mock_in_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "ZKTLS_MODE", "mock")

    with pytest.raises(ValueError):
        settings.validate_zktls_runtime()


def test_validate_zktls_runtime_rejects_mock_in_development(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "ZKTLS_MODE", "mock")

    with pytest.raises(ValueError):
        settings.validate_zktls_runtime()


def test_validate_signer_runtime_rejects_local_in_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "NOTARY_SIGNER_MODE", "local")
    monkeypatch.setattr(settings, "ALLOW_LOCAL_NOTARY_KEYS", False)

    with pytest.raises(ValueError):
        settings.validate_signer_runtime()


def test_validate_signer_runtime_allows_local_in_development(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "NOTARY_SIGNER_MODE", "local")
    monkeypatch.setattr(settings, "ALLOW_LOCAL_NOTARY_KEYS", False)

    settings.validate_signer_runtime()


def test_validate_signer_runtime_remote_requires_url(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "NOTARY_SIGNER_MODE", "remote")
    monkeypatch.setattr(settings, "REMOTE_SIGNER_URL", "")

    with pytest.raises(ValueError):
        settings.validate_signer_runtime()


def test_validate_resolver_registry_runtime_http_requires_url(monkeypatch):
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_MODE", "http")
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_URL", "")

    with pytest.raises(ValueError):
        settings.validate_resolver_registry_runtime()


def test_validate_remote_signer_service_runtime_rejects_local_keypairs_in_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "REMOTE_SIGNER_BACKEND", "local_keypairs")
    monkeypatch.setattr(settings, "ALLOW_LOCAL_NOTARY_KEYS", False)

    with pytest.raises(ValueError):
        settings.validate_remote_signer_service_runtime()


def test_validate_remote_signer_service_runtime_command_requires_command(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "REMOTE_SIGNER_BACKEND", "command")
    monkeypatch.setattr(settings, "REMOTE_SIGNER_COMMAND", "")

    with pytest.raises(ValueError):
        settings.validate_remote_signer_service_runtime()


def test_validate_api_runtime_requires_token_when_auth_enabled(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_API_AUTH", True)
    monkeypatch.setattr(settings, "API_AUTH_TOKEN", "")

    with pytest.raises(ValueError):
        settings.validate_api_runtime()
