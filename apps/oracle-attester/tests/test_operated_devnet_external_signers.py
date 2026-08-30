"""I4A-I2A: operated devnet is a signerless external-service controller."""
from __future__ import annotations

import base64
import importlib.util
import inspect
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from solders.keypair import Keypair

from src.fixed_role_signer_application import create_fixed_role_signer_application
from src.signer_authorization import authorize
from tests.test_fixed_role_signer_applications import _components, _mapping
from tests.test_independent_signer_service import _grant_header


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("operated_devnet_smoke", ROOT / "scripts" / "operated_devnet_smoke.py")
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = smoke
SPEC.loader.exec_module(smoke)


def _artifact(request, *, role: str, signer_id: str, key, grant_id: str):
    return json.loads(base64.b64decode(_grant_header(request, role=role, service_id=signer_id, key=key, grant_id=grant_id)))


def _response(role: str, signer_id: str, key: Keypair, message: bytes):
    import hashlib
    return {
        "schema": "PROPHET_SIGNER_SIGNATURE_V1", "version": "1", "signer_role": role,
        "signer_id": signer_id, "public_key": str(key.pubkey()), "key_version": 1,
        "scope_id": f"scope-{role.lower()}", "settlement_authorization_job_id": "a" * 64,
        "canonical_message_digest": hashlib.sha256(message).hexdigest(), "operation_id": f"operation-{role.lower()}",
        "signature": base64.b64encode(bytes(key.sign_message(message))).decode(), "state": "SIGNED",
    }


def _signers(request, message):
    key_a, key_b = Keypair.from_seed(bytes(range(32))), Keypair.from_seed(bytes(range(32, 64)))
    a = smoke.ExternalSigner("A", "https://signer-a.example", "signer-a", str(key_a.pubkey()), _artifact(request, role="A", signer_id="signer-a", key=Keypair.from_seed(bytes(range(64, 96))), grant_id="a" * 32))
    b = smoke.ExternalSigner("B", "https://signer-b.example", "signer-b", str(key_b.pubkey()), _artifact(request, role="B", signer_id="signer-b", key=Keypair.from_seed(bytes(range(96, 128))), grant_id="c" * 32))
    return a, b, key_a, key_b


@pytest.mark.parametrize("forbidden", (
    "remote_signer_main", "signer_a_main", "signer_b_main", "subprocess",
    "os.environ.copy()", "VaultTransitSignerClient", "ThresholdResolutionSigner",
    "Authorization: Bearer",
))
def test_static_controller_has_no_signer_process_or_secret_capability(forbidden):
    source = (ROOT / "scripts" / "operated_devnet_smoke.py").read_text(encoding="utf-8")
    assert forbidden not in source


def test_controller_generates_a_128_bit_acceptance_run_id(monkeypatch):
    monkeypatch.setattr(smoke.secrets, "token_hex", lambda length: "d" * (length * 2))
    assert smoke._acceptance_run_id(None) == "d" * 32


@pytest.mark.parametrize("run_id", ("A" * 32, "a" * 31, "not-hex"))
def test_controller_rejects_invalid_acceptance_run_id(run_id):
    with pytest.raises(smoke.DevnetSmokeError, match="acceptance_run_id"):
        smoke._acceptance_run_id(run_id)


@pytest.mark.parametrize("name", ("SIGNER_A_VAULT_TOKEN", "SIGNER_B_VAULT_TOKEN", "ISSUER_A_PRIVATE_KEY", "ISSUER_B_PRIVATE_KEY", "SIGNER_A_ADMISSION_TOKEN"))
def test_controller_rejects_signer_or_issuer_secret_environment(name):
    with pytest.raises(smoke.DevnetSmokeError, match="forbidden"):
        smoke._assert_controller_secret_boundary({name: "secret"})


def test_role_distinct_endpoint_and_identity_configuration_is_required():
    request, *_ = __import__("tests.test_signer_authorization", fromlist=["fixture"]).fixture()
    message = b"PROPHET_RESOLVE_V2" + bytes(217)
    a, b, _, _ = _signers(request, message)
    with pytest.raises(smoke.DevnetSmokeError, match="role-distinct"):
        smoke.run_acceptance_flow(request_bytes=json.dumps(request, separators=(",", ":")).encode(), canonical_message=message, signer_a=a, signer_b=smoke.ExternalSigner("B", a.endpoint, b.signer_id, b.public_key, b.grant), post=lambda *_: pytest.fail("post called"))


def test_real_fixed_role_apps_accept_identical_request_and_build_two_of_two_bundle(tmp_path, monkeypatch):
    config_a, engine_a, request, journal_a, vault_a, admission_a, replay_a, issuer_a = _components(tmp_path, monkeypatch, "A")
    config_b, engine_b, _, journal_b, vault_b, admission_b, replay_b, issuer_b = _components(tmp_path, monkeypatch, "B")
    try:
        message = authorize(request=request, config=engine_a._authorization_config, rpc=engine_a._rpc, now_ms=20).canonical_message_bytes
        monkeypatch.delenv("SIGNER_B_VAULT_TOKEN", raising=False)
        app_a = create_fixed_role_signer_application(fixed_role="A", config_value=_mapping(config_a), admission_factory=lambda _: admission_a, engine_factory=lambda _: engine_a, clock=lambda: 20)
        monkeypatch.delenv("SIGNER_A_VAULT_TOKEN", raising=False)
        app_b = create_fixed_role_signer_application(fixed_role="B", config_value=_mapping(config_b), admission_factory=lambda _: admission_b, engine_factory=lambda _: engine_b, clock=lambda: 20)
        client_a, client_b, captured = TestClient(app_a), TestClient(app_b), []
        signer_a = smoke.ExternalSigner("A", "https://signer-a.example", config_a.signer_id, config_a.signer_public_key, _artifact(request, role="A", signer_id=config_a.signer_id, key=issuer_a, grant_id="a" * 32))
        signer_b = smoke.ExternalSigner("B", "https://signer-b.example", config_b.signer_id, config_b.signer_public_key, _artifact(request, role="B", signer_id=config_b.signer_id, key=issuer_b, grant_id="c" * 32))
        def post(endpoint, body, grant):
            captured.append((endpoint, body))
            client = client_a if endpoint == signer_a.endpoint else client_b
            header = base64.b64encode(json.dumps(grant, separators=(",", ":")).encode()).decode()
            response = client.post("/v1/settlement-authorizations", content=body, headers={"Content-Type": "application/json", "X-Prophet-Admission-Grant": header})
            return response.status_code, response.text
        bundle = smoke.run_acceptance_flow(request_bytes=json.dumps(request, separators=(",", ":")).encode(), canonical_message=message, signer_a=signer_a, signer_b=signer_b, post=post)
        assert len(bundle["signatures"]) == 2 and captured[0][1] == captured[1][1]
        assert vault_a.sign_calls == vault_b.sign_calls == 1
    finally:
        journal_a.close(); journal_b.close(); replay_a.close(); replay_b.close()


def test_swapped_grants_and_one_signer_failure_never_make_bundle():
    request, *_ = __import__("tests.test_signer_authorization", fromlist=["fixture"]).fixture()
    message = b"PROPHET_RESOLVE_V2" + bytes(217)
    a, b, key_a, key_b = _signers(request, message)
    responses = {a.endpoint: _response("A", "signer-a", key_a, message), b.endpoint: _response("B", "signer-b", key_b, message)}
    def post(endpoint, body, grant):
        return 403 if grant is b.grant else 200, json.dumps(responses[endpoint])
    with pytest.raises(smoke.DevnetSmokeError, match="no 2-of-2 bundle"):
        smoke.run_acceptance_flow(request_bytes=json.dumps(request, separators=(",", ":")).encode(), canonical_message=message, signer_a=smoke.ExternalSigner("A", a.endpoint, a.signer_id, a.public_key, b.grant), signer_b=smoke.ExternalSigner("B", b.endpoint, b.signer_id, b.public_key, a.grant), post=post)
    calls = []
    def one_signer_fails(endpoint, body, grant):
        calls.append(endpoint)
        return (200, json.dumps(responses[endpoint])) if endpoint == a.endpoint else (503, "failure")
    with pytest.raises(smoke.DevnetSmokeError, match="no 2-of-2 bundle"):
        smoke.run_acceptance_flow(request_bytes=json.dumps(request, separators=(",", ":")).encode(), canonical_message=message, signer_a=a, signer_b=b, post=one_signer_fails)
    assert calls == [a.endpoint, b.endpoint]


def test_wrong_response_identity_and_no_retry_reject():
    request, *_ = __import__("tests.test_signer_authorization", fromlist=["fixture"]).fixture()
    message = b"PROPHET_RESOLVE_V2" + bytes(217)
    a, b, key_a, key_b = _signers(request, message)
    calls = []
    wrong = _response("B", "signer-b", key_b, message)
    with pytest.raises(smoke.DevnetSmokeError, match="identity mismatch"):
        smoke.run_acceptance_flow(request_bytes=json.dumps(request, separators=(",", ":")).encode(), canonical_message=message, signer_a=a, signer_b=b, post=lambda endpoint, body, grant: (calls.append(endpoint) or (200, json.dumps(wrong))))
    assert calls == [a.endpoint]


def test_public_entrypoint_has_no_role_or_retry_controls():
    assert "role" not in inspect.signature(smoke.run_acceptance_flow).parameters
    assert inspect.getsource(smoke.run_acceptance_flow).count("post(signer.endpoint") == 1
