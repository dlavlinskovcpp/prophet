import asyncio
import base64
import json

import pytest
from fastapi.testclient import TestClient
from solders.keypair import Keypair
from starlette.requests import ClientDisconnect

from src.independent_signer_execution import (
    IndependentSignerEngine,
    IndependentSignerExecutionError,
    IndependentSignerVaultAdapter,
)
from src.independent_signer_journal import IndependentSignerBinding, IndependentSignerJournal
from src.independent_signer_service import (
    MAX_AUTHORIZATION_BODY_BYTES,
    IndependentSignerServiceStartupError,
    create_independent_signer_service,
)
from src.signer_authorization import SignerAuthorizationConfig
from tests.test_independent_signer_execution import _Vault, _engine, _service
from tests.test_signer_authorization import fixture


def _service_app(tmp_path, monkeypatch, *, clock=lambda: 20):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    config = engine._service_config
    monkeypatch.setenv(config.admission_token_env, "admission-a")
    return TestClient(create_independent_signer_service(engine=engine, service_config=config, clock=clock)), engine, request, journal, vault


def _headers(**extra):
    return {"Authorization": "Bearer admission-a", "Content-Type": "application/json", **extra}


def _count_engine(monkeypatch, engine):
    calls, original = [], engine.execute
    def counted(request, *, now_ms):
        calls.append((request, now_ms))
        return original(request, now_ms=now_ms)
    monkeypatch.setattr(engine, "execute", counted)
    return calls


def _asgi_request(app, *, headers, messages):
    received, sent = 0, []
    queue = iter(messages)
    async def receive():
        nonlocal received
        received += 1
        item = next(queue)
        if isinstance(item, BaseException):
            raise item
        return item
    async def send(message):
        sent.append(message)
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": "/v1/settlement-authorizations", "raw_path": b"/v1/settlement-authorizations",
        "query_string": b"", "root_path": "", "headers": headers, "client": ("127.0.0.1", 1234), "server": ("test", 80),
    }
    asyncio.run(app(scope, receive, send))
    status = next(message["status"] for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return status, json.loads(body), received


def _raw_headers(*extra):
    return [(b"authorization", b"Bearer admission-a"), (b"content-type", b"application/json"), *extra]


def test_authenticated_valid_request_returns_only_durable_signed_result_and_replays(tmp_path, monkeypatch):
    client, _, request, journal, vault = _service_app(tmp_path, monkeypatch)
    first = client.post("/v1/settlement-authorizations", json=request, headers=_headers())
    second = client.post("/v1/settlement-authorizations", json=request, headers=_headers())
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json() and vault.sign_calls == 1
    payload = first.json()
    assert set(payload) == {
        "schema", "version", "signer_role", "signer_id", "public_key", "key_version", "scope_id",
        "settlement_authorization_job_id", "canonical_message_digest", "operation_id", "signature", "state",
    }
    assert payload["schema"] == "PROPHET_SIGNER_SIGNATURE_V1" and len(base64.b64decode(payload["signature"], validate=True)) == 64
    assert "canonical_message" not in payload and journal.get(payload["scope_id"]).state == "SIGNED"
    journal.close()


@pytest.mark.parametrize("headers", (
    {},
    {"Authorization": "Basic admission-a"},
    {"Authorization": "Bearer wrong"},
), ids=("missing", "wrong_scheme", "wrong_token"))
def test_admission_rejects_invalid_bearer_before_engine_and_body_parsing(tmp_path, monkeypatch, headers):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    response = client.post("/v1/settlement-authorizations", content=b"{" * (MAX_AUTHORIZATION_BODY_BYTES + 1), headers=headers)
    assert response.status_code == 401 and calls == [] and vault.sign_calls == 0
    journal.close()


def test_duplicate_authorization_headers_reject_before_engine(tmp_path, monkeypatch):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    response = client.request("POST", "/v1/settlement-authorizations", content=json.dumps(request), headers=[
        ("Authorization", "Bearer admission-a"), ("Authorization", "Bearer admission-a"), ("Content-Type", "application/json"),
    ])
    assert response.status_code == 401 and calls == [] and vault.sign_calls == 0
    journal.close()


def test_admission_tokens_are_local_per_signer_and_missing_token_fails_startup(tmp_path, monkeypatch):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    import src.independent_signer_service as service_module
    observed, real_getenv = [], service_module.os.getenv
    monkeypatch.setattr(service_module.os, "getenv", lambda name, default="": observed.append(name) or real_getenv(name, default))
    create_independent_signer_service(engine=engine, service_config=engine._service_config, clock=lambda: 20)
    assert "SIGNER_A_ADMISSION_TOKEN" in observed and "SIGNER_B_ADMISSION_TOKEN" not in observed
    monkeypatch.delenv("SIGNER_A_ADMISSION_TOKEN")
    with pytest.raises(IndependentSignerServiceStartupError):
        create_independent_signer_service(engine=engine, service_config=engine._service_config)
    journal.close()


def test_signer_b_service_reads_only_its_own_admission_token(tmp_path, monkeypatch):
    request, auth_a, rpc, *_ = fixture()
    key_b = Keypair.from_seed(bytes(range(32, 64)))
    config_b = _service(key_b, role="B")
    auth_b = SignerAuthorizationConfig(
        "B", auth_a.counterpart_notary_public_key, auth_a.own_notary_public_key,
        auth_a.verifier_a, auth_a.verifier_b, auth_a.expected_cluster_genesis_hash, auth_a.expected_program_id,
    )
    journal = IndependentSignerJournal(tmp_path / "signer-b.sqlite", binding=IndependentSignerBinding("B", "signer-b", str(key_b.pubkey()), 1))
    monkeypatch.setenv("SIGNER_B_VAULT_TOKEN", "vault-b")
    vault = IndependentSignerVaultAdapter(config_b, transport=_Vault(key_b))
    engine = IndependentSignerEngine(service_config=config_b, authorization_config=auth_b, journal=journal, rpc=rpc, vault=vault)
    monkeypatch.setenv("SIGNER_B_ADMISSION_TOKEN", "admission-b")
    import src.independent_signer_service as service_module
    observed, real_getenv = [], service_module.os.getenv
    monkeypatch.setattr(service_module.os, "getenv", lambda name, default="": observed.append(name) or real_getenv(name, default))
    create_independent_signer_service(engine=engine, service_config=config_b, clock=lambda: 20)
    assert "SIGNER_B_ADMISSION_TOKEN" in observed and "SIGNER_A_ADMISSION_TOKEN" not in observed
    journal.close()


def test_content_type_and_body_framing_reject_before_engine(tmp_path, monkeypatch):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    assert client.post("/v1/settlement-authorizations", json=request, headers={"Authorization": "Bearer admission-a", "Content-Type": "text/plain"}).status_code == 415
    assert client.post("/v1/settlement-authorizations", content=b"x", headers=_headers(**{"Content-Length": str(MAX_AUTHORIZATION_BODY_BYTES + 1)})).status_code == 413
    streamed = (chunk for chunk in (b"x" * MAX_AUTHORIZATION_BODY_BYTES, b"x"))
    assert client.request("POST", "/v1/settlement-authorizations", content=streamed, headers=_headers()).status_code == 413
    assert calls == [] and vault.sign_calls == 0
    journal.close()


@pytest.mark.parametrize("body", (
    b"\xff",
    b"{",
    b"[]",
    b"true",
    b'{"schema":"x","schema":"x"}',
), ids=("invalid_utf8", "malformed", "array", "scalar", "duplicate_key"))
def test_strict_json_rejects_before_engine(tmp_path, monkeypatch, body):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    response = client.post("/v1/settlement-authorizations", content=body, headers=_headers())
    assert response.status_code == 400 and calls == [] and vault.sign_calls == 0
    journal.close()


@pytest.mark.parametrize("field, value", (
    ("now_ms", 0),
    ("outcome", "NO"),
    ("canonical_message", "00" * 235),
    ("vault_key_name", "attacker"),
    ("signer_role", "B"),
), ids=("caller_clock", "outcome", "message", "vault_key", "signer_role"))
def test_caller_authoritative_field_injection_cannot_produce_signature(tmp_path, monkeypatch, field, value):
    client, _, request, journal, vault = _service_app(tmp_path, monkeypatch)
    response = client.post("/v1/settlement-authorizations", json={**request, field: value}, headers=_headers())
    assert response.status_code == 422 and vault.sign_calls == 0
    journal.close()


def test_local_clock_is_injected_authority_and_invalid_values_fail_before_engine(tmp_path, monkeypatch):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch, clock=lambda: 20)
    calls = _count_engine(monkeypatch, engine)
    assert client.post("/v1/settlement-authorizations", json=request, headers=_headers()).status_code == 200
    assert calls[0][1] == 20
    journal.close()
    for invalid in (True, False, "20", -1):
        client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch, clock=lambda value=invalid: value)
        calls = _count_engine(monkeypatch, engine)
        assert client.post("/v1/settlement-authorizations", json=request, headers=_headers()).status_code == 503
        assert calls == [] and vault.sign_calls == 0
        journal.close()


def test_engine_rejections_and_ambiguity_are_generic_and_do_not_leak_internals(tmp_path, monkeypatch):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    request["cluster_genesis_hash"] = "00" * 32
    rejected = client.post("/v1/settlement-authorizations", json=request, headers=_headers())
    assert rejected.status_code == 422 and rejected.json() == {"error": "authorization_rejected"}
    monkeypatch.setattr(engine, "execute", lambda *args, **kwargs: (_ for _ in ()).throw(IndependentSignerExecutionError("vault path / secret")))
    ambiguous = client.post("/v1/settlement-authorizations", json=request, headers=_headers())
    assert ambiguous.status_code == 409 and ambiguous.json() == {"error": "signing_not_completed"}
    journal.close()


def test_health_ready_and_documentation_endpoints_do_not_expose_signing_surface(tmp_path, monkeypatch):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    assert client.get("/health").json() == {"ok": True}
    assert client.get("/ready").json() == {"ready": True}
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert vault.sign_calls == 0
    journal.close()


@pytest.mark.parametrize("headers, expected", (
    (_raw_headers((b"content-length", b"10"), (b"content-length", b"11")), 400),
    (_raw_headers((b"content-length", b"10"), (b"content-length", b"10")), 400),
    (_raw_headers((b"content-length", b" 10")), 400),
    (_raw_headers((b"content-length", str(MAX_AUTHORIZATION_BODY_BYTES + 1).encode("ascii"))), 413),
), ids=("conflicting", "identical_duplicate", "malformed", "oversized"))
def test_raw_content_length_framing_rejects_before_body_and_engine(tmp_path, monkeypatch, headers, expected):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    status, payload, receives = _asgi_request(client.app, headers=headers, messages=[{"type": "http.request", "body": b"{}", "more_body": False}])
    assert status == expected and calls == [] and vault.sign_calls == 0 and receives == 0
    assert payload["error"] in {"invalid_request", "request_too_large"}
    journal.close()


def test_raw_streaming_limit_and_fragmentation_are_cumulative(tmp_path, monkeypatch):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    raw = json.dumps(request, separators=(",", ":")).encode("utf-8")
    exact = raw + b" " * (MAX_AUTHORIZATION_BODY_BYTES - len(raw))
    chunks = [{"type": "http.request", "body": exact[index:index + 257], "more_body": index + 257 < len(exact)} for index in range(0, len(exact), 257)]
    status, payload, receives = _asgi_request(client.app, headers=_raw_headers(), messages=chunks)
    assert status == 200 and payload["state"] == "SIGNED" and receives == len(chunks)
    journal.close()

    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    chunks = [{"type": "http.request", "body": exact[index:index + 257], "more_body": True} for index in range(0, len(exact), 257)]
    chunks.extend((
        {"type": "http.request", "body": b"x", "more_body": True},
        {"type": "http.request", "body": b"unread-after-limit", "more_body": False},
    ))
    status, payload, receives = _asgi_request(client.app, headers=_raw_headers(), messages=chunks)
    assert status == 413 and payload == {"error": "request_too_large"} and calls == [] and vault.sign_calls == 0
    assert receives < len(chunks)
    journal.close()


def test_unauthorized_asgi_request_never_consumes_body(tmp_path, monkeypatch):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    status, payload, receives = _asgi_request(client.app, headers=[(b"content-type", b"application/json")], messages=[{"type": "http.request", "body": b"not-consumed", "more_body": False}])
    assert status == 401 and payload == {"error": "unauthorized"} and receives == 0 and calls == [] and vault.sign_calls == 0
    journal.close()


@pytest.mark.parametrize("failure", (ClientDisconnect(), RuntimeError("receive transport failure")), ids=("client_disconnect", "receive_failure"))
def test_stream_disconnect_fails_closed_before_engine_without_detail_leak(tmp_path, monkeypatch, failure):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    status, payload, receives = _asgi_request(client.app, headers=_raw_headers(), messages=[
        {"type": "http.request", "body": b'{"schema"', "more_body": True}, failure,
    ])
    assert status == 400 and payload == {"error": "invalid_request"} and receives == 2 and calls == [] and vault.sign_calls == 0
    journal.close()


@pytest.mark.parametrize("body", (
    b'{"verifier_a_attestation":{"payload":{},"payload":{}}}',
    b'{"value":NaN}',
    b'{"value":Infinity}',
    b'{"value":-Infinity}',
), ids=("nested_duplicate", "nan", "infinity", "negative_infinity"))
def test_nested_duplicate_keys_and_nonstandard_json_constants_reject_before_engine(tmp_path, monkeypatch, body):
    client, engine, request, journal, vault = _service_app(tmp_path, monkeypatch)
    calls = _count_engine(monkeypatch, engine)
    response = client.post("/v1/settlement-authorizations", content=body, headers=_headers())
    assert response.status_code == 400 and calls == [] and vault.sign_calls == 0
    journal.close()
