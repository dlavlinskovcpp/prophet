from fastapi.testclient import TestClient
import yaml

from src.coordinator_service import create_coordinator_service
from src.coordinator_service_bootstrap import build_coordinator_service
from src.verifier_service_client import VerifierClientTransportError


H = lambda byte: f"{byte:02x}" * 32


def _setup(path, *, a_answers=None, b_answers=None, request_max_bytes=100_000):
    from tests.test_resolution_coordinator import _fixture

    coordinator, state, client_a, client_b, definition, evidence, trust, result_a, result_b = _fixture(path, a_answers=a_answers, b_answers=b_answers)
    app = create_coordinator_service(coordinator=coordinator, state=state, auth_token="secret", request_max_bytes=request_max_bytes, request_timeout_seconds=3)
    return TestClient(app), state, client_a, client_b, definition, evidence, trust, result_a, result_b


def _payload(definition, evidence, trust):
    return {"market": H(1), "resolver_definition": definition, "evidence": evidence, "trust_model": trust}


def _headers(**extra):
    return {"Authorization": "Bearer secret", **extra}


def test_health_ready_metrics_and_authentication(tmp_path):
    client, _, _, _, definition, evidence, trust, *_ = _setup(tmp_path / "state.sqlite")
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/metrics").status_code == 200
    payload = _payload(definition, evidence, trust)
    assert client.post("/v1/resolve", json=payload).status_code == 401
    assert client.post("/v1/resolve", json=payload, headers={"Authorization": "Basic secret"}).status_code == 401
    assert client.post("/v1/resolve", json=payload, headers={"Authorization": "Bearer wrong"}).status_code == 401
    invalid = TestClient(create_coordinator_service(request_max_bytes=1, request_timeout_seconds=1, startup_error="invalid"))
    assert invalid.get("/health").status_code == 200 and invalid.get("/ready").status_code == 503


def test_authenticated_resolve_delegates_to_coordinator_and_is_terminally_idempotent(tmp_path):
    client, _, client_a, client_b, definition, evidence, trust, *_ = _setup(tmp_path / "state.sqlite")
    first = client.post("/v1/resolve", json=_payload(definition, evidence, trust), headers=_headers(**{"X-Request-ID": "request-1"}))
    second = client.post("/v1/resolve", json=_payload(definition, evidence, trust), headers=_headers(**{"X-Request-ID": "request-2"}))
    assert first.status_code == second.status_code == 200
    assert first.json()["state"] == second.json()["state"] == "AGREED"
    assert first.json()["job_id"] == second.json()["job_id"]
    assert len(client_a.calls) == len(client_b.calls) == 1


def test_conflict_status_lookup_and_correlation_do_not_call_verifiers(tmp_path):
    from tests.test_resolution_coordinator import _result_with

    client, _, client_a, client_b, definition, evidence, trust, _, result_b = _setup(tmp_path / "state.sqlite", b_answers=[])
    client_b.answers = [_result_with(result_b, outcome="NO", status="VERIFIED")]
    resolved = client.post("/v1/resolve", json=_payload(definition, evidence, trust), headers=_headers(**{"X-Request-ID": "same-id"}))
    assert resolved.status_code == 200 and resolved.json()["state"] == "CONFLICT"
    calls = (len(client_a.calls), len(client_b.calls))
    fetched = client.get(f"/v1/resolutions/{resolved.json()['job_id']}", headers=_headers())
    assert fetched.status_code == 200 and fetched.json()["state"] == "CONFLICT" and (len(client_a.calls), len(client_b.calls)) == calls
    assert client.get("/v1/resolutions/not-a-job", headers=_headers()).status_code == 404


def test_partial_b_failure_is_durable_and_later_post_resumes_only_b(tmp_path):
    client, state, client_a, client_b, definition, evidence, trust, _, result_b = _setup(tmp_path / "state.sqlite", b_answers=[VerifierClientTransportError("down")])
    payload = _payload(definition, evidence, trust)
    failed = client.post("/v1/resolve", json=payload, headers=_headers())
    assert failed.status_code == 503 and failed.json()["error"] == "verifier_dependency_unavailable"
    job = state.register_job(market=H(1), resolver_definition=definition, evidence=evidence)
    assert job.state == "A_RECORDED" and job.verifier_a_result is not None and job.verifier_b_result is None
    client_b.answers = [result_b]
    resumed = client.post("/v1/resolve", json=payload, headers=_headers())
    assert resumed.status_code == 200 and resumed.json()["state"] == "AGREED"
    assert len(client_a.calls) == 1 and len(client_b.calls) == 2


def test_request_validation_and_size_limits_prevent_orchestration(tmp_path):
    client, _, client_a, client_b, definition, evidence, trust, *_ = _setup(tmp_path / "state.sqlite")
    assert client.post("/v1/resolve", content=b"{", headers=_headers()).status_code == 400
    assert client.post("/v1/resolve", json={"market": H(1)}, headers=_headers()).status_code == 422
    invalid = _payload(definition, evidence, trust)
    invalid["evidence"] = {**evidence, "definition_hash": "99" * 32}
    assert client.post("/v1/resolve", json=invalid, headers=_headers()).status_code == 422
    small, _, small_a, small_b, small_definition, small_evidence, small_trust, *_ = _setup(tmp_path / "small.sqlite", request_max_bytes=32)
    assert small.post("/v1/resolve", json=_payload(small_definition, small_evidence, small_trust), headers=_headers()).status_code == 413
    assert not client_a.calls and not client_b.calls and not small_a.calls and not small_b.calls


def test_standalone_bootstrap_constructs_validated_coordinator(tmp_path, monkeypatch):
    _, _, _, _, _, _, _, result_a, result_b = _setup(tmp_path / "fixture.sqlite")
    row = lambda url, env, descriptor: {"base_url": url, "auth_token_env": env, "expected_verifier_id": descriptor["adapter_id"], "expected_verifier_version": descriptor["adapter_version"], "expected_verifier_implementation_digest": descriptor["implementation_digest"], "request_timeout_seconds": 1}
    raw = {"schema_version":1,"environment":"localtest","mode":"test","solana":{"cluster":"localnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"coordinator","version":"2.0.0"},"allowed_adapters":["pyth"],"limits":{"request_max_bytes":1024,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"UNUSED"},"coordinator":{"verifier_a":row("http://verifier-a.internal", "A_TOKEN", result_a["verifier"]),"verifier_b":row("http://verifier-b.internal", "B_TOKEN", result_b["verifier"]),"sqlite_path":str(tmp_path / "boot.sqlite"),"internal_auth":{"token_env":"COORDINATOR_TOKEN"},"request_timeout_seconds":2}}
    path = tmp_path / "coordinator.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setenv("PROPHET_COORDINATOR_RUNTIME_CONFIG", str(path))
    monkeypatch.setenv("COORDINATOR_TOKEN", "secret")
    monkeypatch.setenv("A_TOKEN", "a-secret")
    monkeypatch.setenv("B_TOKEN", "b-secret")
    with TestClient(build_coordinator_service()) as client:
        assert client.get("/ready").status_code == 200
