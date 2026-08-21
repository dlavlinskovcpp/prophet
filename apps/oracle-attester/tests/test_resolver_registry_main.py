import importlib

from fastapi.testclient import TestClient

from src.config import settings
from src.resolver import compute_resolver_hash


def _load_app(monkeypatch, tmp_path, *, require_auth=True):
    store_dir = tmp_path / "resolver_store"
    audit_log = tmp_path / "audit" / "resolver-registry.jsonl"

    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "RESOLVER_STORE_DIR", str(store_dir))
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_AUDIT_LOG_PATH", str(audit_log))
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_REQUIRE_AUTH", require_auth)
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_SERVICE_API_KEY", "registry-secret")
    monkeypatch.setattr(settings, "RESOLVER_REGISTRY_MAX_REQUEST_BYTES", 1024)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(settings, "METRICS_ENABLED", True)

    module = importlib.import_module("src.resolver_registry_main")
    module = importlib.reload(module)
    return module, TestClient(module.app), audit_log


def test_resolver_registry_publish_and_get(monkeypatch, tmp_path):
    module, client, audit_log = _load_app(monkeypatch, tmp_path)
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }
    resolver_hash = compute_resolver_hash(resolver_def).hex()
    headers = {"Authorization": "Bearer registry-secret"}

    publish = client.post(
        "/resolvers",
        headers=headers,
        json={"resolver": resolver_def, "expected_hash": resolver_hash, "metadata": {"seed": "test"}},
    )
    assert publish.status_code == 200
    assert publish.json()["resolver_hash"] == resolver_hash
    assert publish.json()["created"] is True

    publish_again = client.post("/resolvers", headers=headers, json={"resolver": resolver_def})
    assert publish_again.status_code == 200
    assert publish_again.json()["created"] is False

    fetched = client.get(f"/resolvers/{resolver_hash}.json", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["resolver"] == resolver_def

    listing = client.get("/resolvers?limit=10", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["count"] == 1
    assert listing.json()["resolvers"][0]["resolver_hash"] == resolver_hash

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["resolver_count"] == 1

    audit_lines = audit_log.read_text(encoding="utf-8").strip().splitlines()
    assert any('"event":"resolver_published"' in line for line in audit_lines)
    assert any(f'"resolver_hash":"{resolver_hash}"' in line for line in audit_lines)

    direct_payload = module._load_resolver_payload(resolver_hash)
    assert direct_payload["path"] == "data.answer"


def test_resolver_registry_requires_auth(monkeypatch, tmp_path):
    _, client, _ = _load_app(monkeypatch, tmp_path, require_auth=True)
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }

    response = client.post("/resolvers", json=resolver_def)
    assert response.status_code == 401


def test_resolver_registry_rejects_hash_mismatch(monkeypatch, tmp_path):
    _, client, _ = _load_app(monkeypatch, tmp_path)
    headers = {"Authorization": "Bearer registry-secret"}
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 7,
    }

    response = client.post(
        "/resolvers",
        headers=headers,
        json={"resolver": resolver_def, "expected_hash": "00" * 32},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "expected_hash does not match canonical resolver hash"
