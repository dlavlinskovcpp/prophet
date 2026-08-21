import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.audit import JsonlAuditLogger
from src.config import settings


def _load_registry_module(monkeypatch, tmp_path, *, max_bytes=32, rate_enabled=False):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "RESOLVER_STORE_DIR", str(tmp_path / "resolver-store"))
    monkeypatch.setattr(
        settings,
        "RESOLVER_REGISTRY_AUDIT_LOG_PATH",
        str(tmp_path / "audit" / "resolver-registry.jsonl"),
    )
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_REQUIRE_AUTH", False)
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_SERVICE_API_KEY", "")
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_MAX_REQUEST_BYTES", max_bytes)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", rate_enabled)
    monkeypatch.setattr(settings, "RATE_LIMIT_MAX_REQUESTS", 2)
    monkeypatch.setattr(settings, "RATE_LIMIT_WINDOW_S", 10)
    monkeypatch.setattr(settings, "RATE_LIMIT_MAX_IDENTITIES", 3)
    monkeypatch.setattr(settings, "METRICS_ENABLED", True)
    module = importlib.import_module("src.resolver_registry_main")
    return importlib.reload(module)


def _streaming_request(chunks, *, headers=()):
    messages = []
    chunks = list(chunks)
    for index, chunk in enumerate(chunks):
        messages.append(
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index != len(chunks) - 1,
            }
        )
    if not messages:
        messages.append({"type": "http.request", "body": b"", "more_body": False})

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/resolvers",
        "raw_path": b"/resolvers",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers],
        "client": ("203.0.113.10", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope, receive)


@pytest.mark.asyncio
async def test_actual_body_small_request_is_accepted(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path, max_bytes=8)
    request = _streaming_request([b"{}", b"  "])
    assert await module._read_bounded_request_body(request, 8) == b"{}  "


def test_declared_oversized_content_length_rejected_immediately(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path, max_bytes=8)
    client = TestClient(module.app)
    response = client.post(
        "/resolvers",
        content=b"{}",
        headers={"Content-Length": "9", "Content-Type": "application/json"},
    )
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_missing_content_length_cannot_bypass_actual_body_limit(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path, max_bytes=8)
    request = _streaming_request([b"1234", b"56789"])
    with pytest.raises(module.RequestBodyTooLarge):
        await module._read_bounded_request_body(request, 8)


@pytest.mark.asyncio
async def test_chunked_stream_stops_on_limit_overflow(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path, max_bytes=8)
    request = _streaming_request(
        [b"123", b"456", b"789"],
        headers=(("transfer-encoding", "chunked"),),
    )
    with pytest.raises(module.RequestBodyTooLarge):
        await module._read_bounded_request_body(request, 8)


@pytest.mark.asyncio
async def test_declared_small_actual_large_body_still_rejected(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path, max_bytes=8)
    request = _streaming_request(
        [b"123456789"],
        headers=(("content-length", "1"),),
    )
    with pytest.raises(module.RequestBodyTooLarge):
        await module._read_bounded_request_body(request, 8)


def test_malformed_content_length_fails_closed(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path, max_bytes=8)
    client = TestClient(module.app)
    response = client.post(
        "/resolvers",
        content=b"{}",
        headers={"Content-Length": "not-a-number", "Content-Type": "application/json"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_exact_request_limit_boundary_is_accepted(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path, max_bytes=8)
    request = _streaming_request([b"1234", b"5678"])
    assert await module._read_bounded_request_body(request, 8) == b"12345678"


@pytest.mark.asyncio
async def test_request_limit_plus_one_is_rejected(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path, max_bytes=8)
    request = _streaming_request([b"12345678", b"9"])
    with pytest.raises(module.RequestBodyTooLarge):
        await module._read_bounded_request_body(request, 8)


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_rate_limiter_normal_semantics_and_active_key_retained(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path)
    clock = _Clock()
    limiter = module.SlidingWindowRateLimiter(
        2,
        10,
        max_identities=3,
        clock=clock,
        cleanup_interval_s=1,
    )
    assert limiter.allow("a")[0] is True
    assert limiter.allow("a")[0] is True
    assert limiter.allow("a")[0] is False
    clock.advance(1.1)
    assert limiter.allow("b")[0] is True
    assert "a" in limiter._hits


def test_rate_limiter_expired_key_removed_deterministically(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path)
    clock = _Clock()
    limiter = module.SlidingWindowRateLimiter(
        2,
        10,
        max_identities=3,
        clock=clock,
        cleanup_interval_s=1,
    )
    limiter.allow("expired")
    clock.advance(11)
    limiter.allow("fresh")
    assert "expired" not in limiter._hits
    assert limiter.identity_count == 1


def test_rate_limiter_cardinality_is_bounded_under_one_shot_identities(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path)
    clock = _Clock()
    limiter = module.SlidingWindowRateLimiter(
        2,
        10,
        max_identities=3,
        clock=clock,
        cleanup_interval_s=1,
    )
    assert all(limiter.allow(f"id-{i}")[0] for i in range(3))
    allowed, _ = limiter.allow("id-over-capacity")
    assert allowed is False
    assert limiter.identity_count == 3
    clock.advance(11)
    assert limiter.allow("id-after-expiry")[0] is True
    assert limiter.identity_count == 1


def _request_with_xff(value):
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"x-forwarded-for", value.encode())],
        "client": ("203.0.113.10", 12345),
        "server": ("testserver", 80),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


def test_xff_default_disabled_uses_direct_peer(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "RATE_LIMIT_TRUST_X_FORWARDED_FOR", False)
    assert module._client_ip(_request_with_xff("198.51.100.99")) == "203.0.113.10"


def test_trusted_xff_mode_uses_valid_forwarded_identity(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "RATE_LIMIT_TRUST_X_FORWARDED_FOR", True)
    assert module._client_ip(_request_with_xff("198.51.100.99, 10.0.0.1")) == "198.51.100.99"


def test_malformed_xff_falls_back_to_direct_peer(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "RATE_LIMIT_TRUST_X_FORWARDED_FOR", True)
    assert module._client_ip(_request_with_xff("not-an-ip")) == "203.0.113.10"


def test_rate_limit_token_identity_never_retains_token_material(monkeypatch, tmp_path):
    module = _load_registry_module(monkeypatch, tmp_path)
    token = "test-only-super-secret-token"
    identity = module._rate_limit_token_identity(token)
    assert token not in identity
    assert len(identity) == 24


def test_resolver_audit_survives_logger_recreation(tmp_path):
    durable = tmp_path / "persistent-audit"
    path = durable / "resolver-registry.jsonl"
    first = JsonlAuditLogger(str(path), "resolver-registry")
    first.write("first_event", {"resolver_hash": "00" * 32})
    del first

    second = JsonlAuditLogger(str(path), "resolver-registry")
    second.write("second_event", {"resolver_hash": "11" * 32})

    text = path.read_text(encoding="utf-8")
    assert '"event":"first_event"' in text
    assert '"event":"second_event"' in text


def test_production_audit_path_must_be_operated_persistent_mount(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "RESOLVER_STORE_DIR", "/app/resolver_store")
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_SERVICE_API_KEY", "test-only")
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_MAX_REQUEST_BYTES", 1024)

    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_AUDIT_LOG_PATH", "audit/local.jsonl")
    with pytest.raises(ValueError):
        settings.validate_resolver_registry_service_runtime()

    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_AUDIT_LOG_PATH", "/tmp/ephemeral.jsonl")
    with pytest.raises(ValueError):
        settings.validate_resolver_registry_service_runtime()

    monkeypatch.setattr(
        settings,
        "RESOLVER_REGISTRY_AUDIT_LOG_PATH",
        "/app/audit/resolver-registry.jsonl",
    )
    settings.validate_resolver_registry_service_runtime()


@pytest.mark.parametrize("environment", ["devnet", "public-devnet", "mainnet-beta"])
def test_operated_registry_audit_mount_is_persistent(environment):
    root = Path(__file__).resolve().parents[3]
    compose = (root / "deploy" / "operated" / environment / "docker-compose.yml").read_text()
    assert "/resolver_store:/app/resolver_store" in compose
    assert "/resolver_audit:/app/audit" in compose
