import importlib
import sys
import types

from fastapi.testclient import TestClient

from src.config import settings
from src.proof_fetcher import LocalFileProofFetcher
from src.types import ResolveResponse


class _DummyService:
    async def resolve_market(self, _req):
        return ResolveResponse(
            signature="sig-123",
            proof_hash_hex="aa",
            public_inputs_hash_hex="bb",
            resolved_ts=1,
        )


class _CountingVerifier:
    def __init__(self):
        self.calls = 0

    def verify(self, **_kwargs):
        self.calls += 1
        return object()


class _ProofRefService:
    def __init__(self, fetcher, verifier):
        self.fetcher = fetcher
        self.verifier = verifier

    async def resolve_market(self, req):
        fetched = self.fetcher.fetch(req.proof_ref or "")
        self.verifier.verify(
            resolver=None,
            proof_bytes=fetched.proof_bytes,
            public_inputs_bytes=fetched.public_inputs_bytes,
        )
        return ResolveResponse(
            signature="should-not-resolve",
            proof_hash_hex="aa",
            public_inputs_hash_hex="bb",
            resolved_ts=1,
        )


def _load_main(monkeypatch, dummy_service):
    fake_attester = types.ModuleType("src.attester")
    fake_attester.service = dummy_service
    monkeypatch.setitem(
        sys.modules,
        "src.attester",
        fake_attester,
    )
    sys.modules.pop("src.main", None)
    import src.main as main_mod

    return importlib.reload(main_mod)


def _set_valid_runtime_defaults(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "ZKTLS_MODE", "reclaim_http")
    monkeypatch.setattr(settings, "REQUIRE_ZKTLS", True)
    monkeypatch.setattr(settings, "RECLAIM_VERIFY_URL", "https://verify.example")
    monkeypatch.setattr(settings, "NOTARY_SIGNER_MODE", "remote")
    monkeypatch.setattr(settings, "REMOTE_SIGNER_URL", "https://signer.example")
    monkeypatch.setattr(settings, "REMOTE_SIGNER_TIMEOUT_S", 5.0)
    monkeypatch.setattr(settings, "REMOTE_SIGNER_REQUIRE_TLS", True)
    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 1_000_000)
    monkeypatch.setattr(settings, "RATE_LIMIT_MAX_REQUESTS", 30)
    monkeypatch.setattr(settings, "PROOF_FETCH_MODE", "http")
    monkeypatch.setattr(settings, "RATE_LIMIT_WINDOW_S", 60)


def test_resolve_requires_auth(monkeypatch):
    _set_valid_runtime_defaults(monkeypatch)
    monkeypatch.setattr(settings, "REQUIRE_API_AUTH", True)
    monkeypatch.setattr(settings, "API_AUTH_TOKEN", "secret")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(settings, "METRICS_ENABLED", True)

    main_mod = _load_main(monkeypatch, _DummyService())
    client = TestClient(main_mod.app)

    payload = {"market": "market-x", "outcome": "YES"}

    r_unauth = client.post("/resolve", json=payload)
    assert r_unauth.status_code == 401

    r_wrong = client.post("/resolve", json=payload, headers={"Authorization": "Bearer wrong"})
    assert r_wrong.status_code == 401

    r_ok = client.post("/resolve", json=payload, headers={"Authorization": "Bearer secret"})
    assert r_ok.status_code == 200
    assert r_ok.json()["signature"] == "sig-123"


def test_resolve_rate_limit(monkeypatch):
    _set_valid_runtime_defaults(monkeypatch)
    monkeypatch.setattr(settings, "REQUIRE_API_AUTH", False)
    monkeypatch.setattr(settings, "API_AUTH_TOKEN", "")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMIT_MAX_REQUESTS", 1)
    monkeypatch.setattr(settings, "RATE_LIMIT_WINDOW_S", 60)
    monkeypatch.setattr(settings, "METRICS_ENABLED", True)

    main_mod = _load_main(monkeypatch, _DummyService())
    client = TestClient(main_mod.app)

    payload = {"market": "market-x", "outcome": "YES"}
    r1 = client.post("/resolve", json=payload)
    r2 = client.post("/resolve", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 429
    assert "Retry-After" in r2.headers


def test_metrics_endpoint_exposes_counters(monkeypatch):
    _set_valid_runtime_defaults(monkeypatch)
    monkeypatch.setattr(settings, "REQUIRE_API_AUTH", False)
    monkeypatch.setattr(settings, "API_AUTH_TOKEN", "")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(settings, "METRICS_ENABLED", True)

    main_mod = _load_main(monkeypatch, _DummyService())
    client = TestClient(main_mod.app)

    client.get("/health")
    client.post("/resolve", json={"market": "market-x", "outcome": "YES"})
    metrics = client.get("/metrics")

    assert metrics.status_code == 200
    body = metrics.text
    assert "prophet_attester_http_requests_total" in body
    assert 'path="/health"' in body
    assert "prophet_attester_resolve_total" in body


def test_resolve_cannot_read_external_file_via_proof_ref(tmp_path, monkeypatch):
    proof_store = tmp_path / "proof-store"
    proof_store.mkdir()
    (proof_store / "pi.bin").write_bytes(b"pi")
    outside = tmp_path / "test-only-secret"
    outside.write_bytes(b"TEST_ONLY_SECRET_BYTES")

    verifier = _CountingVerifier()
    service = _ProofRefService(LocalFileProofFetcher(proof_store), verifier)

    _set_valid_runtime_defaults(monkeypatch)
    monkeypatch.setattr(settings, "REQUIRE_API_AUTH", True)
    monkeypatch.setattr(settings, "API_AUTH_TOKEN", "secret")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(settings, "METRICS_ENABLED", True)

    main_mod = _load_main(monkeypatch, service)
    client = TestClient(main_mod.app)
    response = client.post(
        "/resolve",
        headers={"Authorization": "Bearer secret"},
        json={
            "market": "market-x",
            "outcome": "YES",
            "proof_ref": f"file:{outside}:pi.bin",
        },
    )

    assert response.status_code == 409
    assert verifier.calls == 0
    assert str(outside) not in response.text
    assert "TEST_ONLY_SECRET_BYTES" not in response.text
