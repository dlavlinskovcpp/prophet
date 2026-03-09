import json

import httpx
import pytest

from src.resolver import compute_resolver_hash
from src.resolver_registry import DirectoryResolverRegistry, HttpResolverRegistry


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
