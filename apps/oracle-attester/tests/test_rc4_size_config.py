import pytest

from src.config import settings


def test_registry_client_response_limit_must_be_positive(monkeypatch):
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_MODE", "directory")
    monkeypatch.setattr(settings, "RESOLVER_STORE_DIR", ".")
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_CACHE_TTL_S", 1)
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_CACHE_MAX_ENTRIES", 1)
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_MAX_RESPONSE_BYTES", 0)
    with pytest.raises(ValueError, match="RESOLVER_REGISTRY_MAX_RESPONSE_BYTES"):
        settings.validate_resolver_registry_runtime()


def test_proof_http_response_limit_must_be_positive(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "PROOF_FETCH_MODE", "local")
    monkeypatch.setattr(settings, "PROOF_STORE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "PROOF_HTTP_MAX_RESPONSE_BYTES", 0)
    monkeypatch.setattr(settings, "PROOF_MAX_BYTES", 1)
    monkeypatch.setattr(settings, "PUBLIC_INPUTS_MAX_BYTES", 1)
    with pytest.raises(ValueError, match="PROOF_HTTP_MAX_RESPONSE_BYTES"):
        settings.validate_proof_fetch_runtime()


def test_rate_limit_identity_cap_must_be_positive(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_API_AUTH", False)
    monkeypatch.setattr(settings, "RATE_LIMIT_MAX_REQUESTS", 1)
    monkeypatch.setattr(settings, "RATE_LIMIT_WINDOW_S", 1)
    monkeypatch.setattr(settings, "RATE_LIMIT_MAX_IDENTITIES", 0)
    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 1)
    with pytest.raises(ValueError, match="RATE_LIMIT_MAX_IDENTITIES"):
        settings.validate_api_runtime()
