import time

from fastapi.testclient import TestClient
import yaml

from src.verifier_service import create_verifier_service
from src.verifier_service_bootstrap import build_service


def _services(limit=100_000, timeout=1):
    from tests.test_dual_verifier_runtime_independence import _runtimes
    namespace, definition, evidence, runtime_a, runtime_b, primary_factory, independent_factory, checker = _runtimes()
    common = {"auth_token": "secret", "request_max_bytes": limit, "request_timeout_seconds": timeout}
    app_a = create_verifier_service(runtime=runtime_a, expected_verifier_id="prophet.verifier.runtime.a", expected_verifier_version="2.0.0", **common)
    app_b = create_verifier_service(runtime=runtime_b, expected_verifier_id="prophet.verifier.runtime.b", expected_verifier_version="2.0.0", **common)
    return namespace, definition, evidence, TestClient(app_a), TestClient(app_b), primary_factory, independent_factory, checker


def _payload(definition, evidence, trust): return {"resolver_definition": definition, "evidence": evidence, "trust_model": trust}


def test_verifier_services_health_ready_metrics_and_invalid_startup():
    _, _, _, client_a, client_b, _, _, _ = _services()
    for client in (client_a, client_b):
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200
        assert client.get("/metrics").status_code == 200
    invalid = TestClient(create_verifier_service(runtime=None, auth_token="", expected_verifier_id="prophet.verifier.runtime.a", expected_verifier_version="2.0.0", request_max_bytes=1, request_timeout_seconds=1, startup_error="invalid"))
    assert invalid.get("/health").status_code == 200 and invalid.get("/ready").status_code == 503


def test_verifier_service_auth_and_request_validation():
    namespace, definition, evidence, client_a, _, _, _, _ = _services(limit=32)
    payload = _payload(definition, evidence, namespace["_trust"]())
    assert client_a.post("/v1/verify", json=payload).status_code == 401
    assert client_a.post("/v1/verify", json=payload, headers={"Authorization": "Basic secret"}).status_code == 401
    assert client_a.post("/v1/verify", json=payload, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client_a.post("/v1/verify", content=b"{" * 33, headers={"Authorization": "Bearer secret"}).status_code == 413
    assert client_a.post("/v1/verify", content=b"{", headers={"Authorization": "Bearer secret"}).status_code == 400
    assert client_a.post("/v1/verify", json={**payload, "extra": True}, headers={"Authorization": "Bearer secret"}).status_code == 413


def test_verifier_services_delegate_once_to_their_own_runtime():
    namespace, definition, evidence, client_a, client_b, primary_factory, independent_factory, checker = _services()
    payload, headers = _payload(definition, evidence, namespace["_trust"]()), {"Authorization": "Bearer secret", "X-Request-ID": "request-1"}
    a_before, b_before = primary_factory.calls, independent_factory.calls
    response_a = client_a.post("/v1/verify", json=payload, headers=headers)
    response_b = client_b.post("/v1/verify", json=payload, headers=headers)
    assert response_a.status_code == response_b.status_code == 200
    assert response_a.json()["result"] == response_b.json()["result"] == "VERIFIED"
    assert response_a.json()["verifier"]["adapter_id"] == "prophet.verifier.runtime.a"
    assert response_b.json()["verifier"]["adapter_id"] == "prophet.verifier.runtime.b"
    assert response_a.headers["X-Request-ID"] == "request-1"
    assert primary_factory.calls == a_before + 1 and independent_factory.calls == b_before + 1 and checker.calls == 1
    assert "verifier_http_requests_total" in client_a.get("/metrics").text


def test_verifier_service_preserves_canonical_rejection_and_rejects_bad_input():
    namespace, definition, evidence, client_a, _, _, _, _ = _services()
    headers = {"Authorization": "Bearer secret"}
    bad_binding = _payload(definition, {**evidence, "definition_hash": "99" * 32}, namespace["_trust"]())
    assert client_a.post("/v1/verify", json=bad_binding, headers=headers).status_code == 422
    runtime = client_a.app.state.runtime
    adapter = runtime.adapter_factory.create(definition)
    acquired = adapter.acquire(definition, namespace["ZkTlsMaterial"](b"invalid", b'{"schema":"example.response","schema_version":"1","data":{"outcome":"YES"}}', "1", "90", "api.example", "1e" * 32, "1f" * 32))
    rejected = namespace["normalize_evidence"](acquired, definition_hash=namespace["resolver_v2"].resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "zktls"}, provenance={"proof_hash": "08" * 32})
    response = client_a.post("/v1/verify", json=_payload(definition, rejected, namespace["_trust"]()), headers=headers)
    assert response.status_code == 200 and response.json()["result"] == "REJECTED"


def test_verifier_service_timeout_fails_closed():
    class SlowRuntime:
        verifier_descriptor = {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": "prophet.verifier.runtime.a", "adapter_version": "2.0.0", "implementation_digest": "46" * 32}
        def verify(self, **kwargs): time.sleep(0.05); return {"result": "VERIFIED"}
    client = TestClient(create_verifier_service(runtime=SlowRuntime(), auth_token="secret", expected_verifier_id="prophet.verifier.runtime.a", expected_verifier_version="2.0.0", request_max_bytes=100_000, request_timeout_seconds=0.001))
    payload = {"resolver_definition": {}, "evidence": {}, "trust_model": {}}
    assert client.post("/v1/verify", json=payload, headers={"Authorization": "Bearer secret"}).status_code == 503


def test_service_bootstrap_constructs_only_its_expected_runtime(tmp_path, monkeypatch):
    def config(identity):
        return {
            "schema_version": 1,
            "environment": "localtest",
            "mode": "test",
            "solana": {"cluster": "localnet", "genesis_hash": "genesis", "prophet_program_id": "program"},
            "resolver_v2": {"schema_version": 2},
            "verifier": {"implementation_id": identity, "version": "2.0.0"},
            "allowed_adapters": ["zktls"],
            "zktls": {"provider_id": "deterministic-test-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]},
            "limits": {"request_max_bytes": 1024, "request_timeout_seconds": 1},
            "freshness": {"default_max_evidence_age_seconds": 300, "default_max_verification_age_seconds": 60},
            "internal_auth": {"token_env": "PROPHET_VERIFIER_INTERNAL_TOKEN"},
        }

    path = tmp_path / "runtime.yaml"
    monkeypatch.setenv("PROPHET_VERIFIER_RUNTIME_CONFIG", str(path))
    monkeypatch.setenv("PROPHET_VERIFIER_INTERNAL_TOKEN", "secret")
    for kind, identity in (("a", "prophet.verifier.runtime.a"), ("b", "prophet.verifier.runtime.b")):
        path.write_text(yaml.safe_dump(config(identity)), encoding="utf-8")
        app = build_service(kind)
        assert TestClient(app).get("/ready").status_code == 200
        assert app.state.runtime.verifier_descriptor["adapter_id"] == identity

    path.write_text(yaml.safe_dump(config("prophet.verifier.runtime.b")), encoding="utf-8")
    assert TestClient(build_service("a")).get("/ready").status_code == 503
