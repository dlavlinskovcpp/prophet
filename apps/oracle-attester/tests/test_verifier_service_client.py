import copy
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from src.resolver_v2_pipeline import resolver_v2
from src.runtime_config import CoordinatorVerifierServiceConfig, parse_runtime_config
from src.verifier_service_client import (
    VerifierClientAuthenticationError,
    VerifierClientBindingMismatch,
    VerifierClientIdentityMismatch,
    VerifierClientMalformedResponse,
    VerifierClientRemoteServiceError,
    VerifierClientTimeout,
    VerifierClientTransportError,
    VerifierServiceClient,
)


class _Server:
    def __init__(self, *, body=b"{}", status=200, headers=None, delay=0):
        self.body, self.status, self.headers, self.delay, self.requests = body, status, headers or {}, delay, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                outer.requests.append((self.path, dict(self.headers), self.rfile.read(length)))
                if outer.delay:
                    time.sleep(outer.delay)
                self.send_response(outer.status)
                for key, value in outer.headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                try:
                    self.wfile.write(outer.body)
                except BrokenPipeError:
                    pass

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


def _fixture():
    from tests.test_dual_verifier_runtime_independence import _runtimes

    namespace, definition, evidence, runtime_a, runtime_b, *_ = _runtimes()
    trust = namespace["_trust"]()
    return definition, evidence, trust, runtime_a.verify(resolver_definition=definition, evidence=evidence, trust_model=trust), runtime_b.verify(resolver_definition=definition, evidence=evidence, trust_model=trust)


def _client(server, result, *, slot="A", timeout=1):
    descriptor = result["verifier"]
    config = CoordinatorVerifierServiceConfig(server.url, "CLIENT_TOKEN", descriptor["adapter_id"], descriptor["adapter_version"], descriptor["implementation_digest"], timeout)
    return VerifierServiceClient(slot=slot, config=config, bearer_token="secret", response_max_bytes=100_000)


def _verify(client, definition, evidence, trust):
    return client.verify(resolver_definition=definition, evidence=evidence, trust_model=trust, request_id="request-1")


def test_identity_bound_a_and_b_clients_send_canonical_request_and_bearer_token():
    definition, evidence, trust, result_a, result_b = _fixture()
    for slot, result in (("A", result_a), ("B", result_b)):
        with _Server(body=resolver_v2.canonical_json_bytes(result)) as server:
            returned = _verify(_client(server, result, slot=slot), definition, evidence, trust)
            assert returned == result
            path, headers, sent = server.requests[0]
            assert path == "/v1/verify" and headers["Authorization"] == "Bearer secret"
            assert json.loads(sent) == {"resolver_definition": definition, "evidence": evidence, "trust_model": trust}


@pytest.mark.parametrize("status,error", [(401, VerifierClientAuthenticationError), (500, VerifierClientRemoteServiceError), (302, VerifierClientRemoteServiceError)])
def test_remote_auth_server_errors_and_redirects_fail_closed(status, error):
    definition, evidence, trust, result_a, _ = _fixture()
    with _Server(status=status, headers={"Location": "http://127.0.0.1/other"}) as server:
        with pytest.raises(error):
            _verify(_client(server, result_a), definition, evidence, trust)


def test_malformed_json_and_verification_result_are_rejected():
    definition, evidence, trust, result_a, _ = _fixture()
    for body in (b"not-json", b"{}"):
        with _Server(body=body) as server:
            with pytest.raises(VerifierClientMalformedResponse):
                _verify(_client(server, result_a), definition, evidence, trust)


def test_wrong_verifier_identity_and_request_binding_are_rejected():
    definition, evidence, trust, result_a, result_b = _fixture()
    with _Server(body=resolver_v2.canonical_json_bytes(result_b)) as server:
        with pytest.raises(VerifierClientIdentityMismatch):
            _verify(_client(server, result_a), definition, evidence, trust)
    mismatched = copy.deepcopy(result_a)
    mismatched["definition_hash"] = "09" * 32
    resolver_v2.validate_verification_result(mismatched)
    with _Server(body=resolver_v2.canonical_json_bytes(mismatched)) as server:
        with pytest.raises(VerifierClientBindingMismatch):
            _verify(_client(server, result_a), definition, evidence, trust)


def test_timeout_connection_failure_and_no_local_fallback():
    definition, evidence, trust, result_a, _ = _fixture()
    with _Server(body=resolver_v2.canonical_json_bytes(result_a), delay=0.05) as server:
        with pytest.raises(VerifierClientTimeout):
            _verify(_client(server, result_a, timeout=0.001), definition, evidence, trust)
    unavailable = CoordinatorVerifierServiceConfig("http://127.0.0.1:1", "CLIENT_TOKEN", result_a["verifier"]["adapter_id"], result_a["verifier"]["adapter_version"], result_a["verifier"]["implementation_digest"], 1)
    client = VerifierServiceClient(slot="A", config=unavailable, bearer_token="secret", response_max_bytes=100_000)
    with pytest.raises(VerifierClientTransportError):
        _verify(client, definition, evidence, trust)


def test_runtime_configuration_loads_external_a_b_secrets_and_rejects_missing(monkeypatch):
    _, _, _, result_a, result_b = _fixture()
    descriptor_a, descriptor_b = result_a["verifier"], result_b["verifier"]
    client_row = lambda url, token_env, descriptor: {"base_url": url, "auth_token_env": token_env, "expected_verifier_id": descriptor["adapter_id"], "expected_verifier_version": descriptor["adapter_version"], "expected_verifier_implementation_digest": descriptor["implementation_digest"], "request_timeout_seconds": 1}
    raw = {"schema_version":1,"environment":"public-devnet","mode":"test","solana":{"cluster":"devnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"coordinator-test","version":"2.0.0"},"allowed_adapters":["pyth"],"limits":{"request_max_bytes":100000,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"INTERNAL"},"coordinator":{"verifier_a":client_row("http://verifier-a.internal:8301", "A_TOKEN", descriptor_a),"verifier_b":client_row("https://verifier-b.internal", "B_TOKEN", descriptor_b),"sqlite_path":"/private/tmp/coordinator.sqlite","internal_auth":{"token_env":"COORDINATOR_TOKEN"},"request_timeout_seconds":2}}
    config = parse_runtime_config(raw)
    with pytest.raises(VerifierClientAuthenticationError):
        VerifierServiceClient.from_runtime(config, slot="A")
    monkeypatch.setenv("A_TOKEN", "a-secret")
    client = VerifierServiceClient.from_runtime(config, slot="A")
    assert client.slot == "A" and "a-secret" not in config.fingerprint()
    client.close()
    raw["coordinator"]["verifier_a"]["base_url"] = "https://user:password@verifier-a.internal/#fragment"
    with pytest.raises(ValueError):
        parse_runtime_config(raw)
