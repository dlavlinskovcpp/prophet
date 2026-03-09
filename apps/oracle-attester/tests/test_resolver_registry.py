import json

import httpx
import pytest

from src.resolver import compute_resolver_hash
from src.resolver_registry import CachingResolverRegistry, DirectoryResolverRegistry, HttpResolverRegistry


def test_directory_resolver_registry_loads_and_verifies_hash(tmp_path):
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }
    resolver_hash = compute_resolver_hash(resolver_def)
    (tmp_path / f"{resolver_hash.hex()}.json").write_text(
        json.dumps(resolver_def),
        encoding="utf-8",
    )

    registry = DirectoryResolverRegistry(str(tmp_path))
    loaded = registry.load(resolver_hash)

    assert loaded.url == resolver_def["url"]
    assert loaded.target_value == resolver_def["target_value"]


def test_http_resolver_registry_loads_nested_payload(monkeypatch):
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }
    resolver_hash = compute_resolver_hash(resolver_def)
    seen = {}

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url, headers=None):
            seen["url"] = url
            seen["headers"] = headers
            req = httpx.Request("GET", url)
            return httpx.Response(200, json={"resolver": resolver_def}, request=req)

    monkeypatch.setattr(httpx, "Client", MockClient)

    registry = HttpResolverRegistry("https://registry.example/resolvers", "k", 3.0)
    loaded = registry.load(resolver_hash)

    assert seen["url"].endswith(f"/{resolver_hash.hex()}.json")
    assert seen["headers"]["Authorization"] == "Bearer k"
    assert loaded.path == resolver_def["path"]


def test_http_resolver_registry_rejects_hash_mismatch(monkeypatch):
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 7,
    }
    requested_hash = bytes([5] * 32)

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url, headers=None):
            req = httpx.Request("GET", url)
            return httpx.Response(200, json=resolver_def, request=req)

    monkeypatch.setattr(httpx, "Client", MockClient)

    registry = HttpResolverRegistry("https://registry.example/resolvers", "", 3.0)
    with pytest.raises(ValueError):
        registry.load(requested_hash)


def test_caching_resolver_registry_reuses_cached_entry():
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }
    resolver_hash = compute_resolver_hash(resolver_def)

    class InnerRegistry:
        mode = "memory"

        def __init__(self):
            self.calls = 0

        def load(self, resolver_hash_arg):
            assert resolver_hash_arg == resolver_hash
            self.calls += 1
            return DirectoryResolverRegistry._parse_and_verify(resolver_hash, resolver_def)

        def health(self):
            return {"mode": self.mode}

    inner = InnerRegistry()
    registry = CachingResolverRegistry(inner, ttl_s=60.0, max_entries=4, allow_stale_on_error=True)

    first = registry.load(resolver_hash)
    second = registry.load(resolver_hash)

    assert first.path == second.path
    assert inner.calls == 1
    assert registry.health()["cache_hits"] == 1


def test_caching_resolver_registry_serves_stale_on_backend_error():
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }
    resolver_hash = compute_resolver_hash(resolver_def)

    class FlakyRegistry:
        mode = "memory"

        def __init__(self):
            self.calls = 0

        def load(self, _resolver_hash):
            self.calls += 1
            if self.calls == 1:
                return DirectoryResolverRegistry._parse_and_verify(resolver_hash, resolver_def)
            raise RuntimeError("registry unavailable")

        def health(self):
            return {"mode": self.mode}

    registry = CachingResolverRegistry(FlakyRegistry(), ttl_s=0.001, max_entries=4, allow_stale_on_error=True)

    first = registry.load(resolver_hash)
    import time
    time.sleep(0.01)
    second = registry.load(resolver_hash)

    assert first.path == second.path
    assert registry.health()["cache_stale_hits"] == 1
