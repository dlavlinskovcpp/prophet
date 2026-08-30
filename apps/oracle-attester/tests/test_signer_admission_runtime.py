from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import rfc8785
from fastapi.testclient import TestClient
from solders.keypair import Keypair

from src.admission_grant_replay_journal import AdmissionGrantReplayJournal
from src.independent_signer_service import create_independent_signer_service
from src.signer_admission_grant import GRANT_DOMAIN, GRANT_SCHEMA, GRANT_SIGNATURE_SCHEMA, StrictSignerAuthorizationRequestV1, admission_request_binding
from src.signer_admission_runtime import SignerAdmissionRuntime
from src.signer_admission_grant import AdmissionGrantContext, AdmissionIssuerKeyV1
from tests.test_independent_signer_execution import _engine


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def _grant(request, *, role="A", service_id="signer-a", key=None, grant_id="c" * 32):
    key = key or Keypair.from_seed(bytes(range(64, 96)))
    strict = StrictSignerAuthorizationRequestV1.from_mapping(request)
    _, _, digest = admission_request_binding(strict)
    grant = {"schema": GRANT_SCHEMA, "version": 1, "grant_id": grant_id, "environment": "public-devnet", "git_sha": "a" * 40, "evidence_set_id": "evidence-001", "acceptance_run_id": "b" * 32, "signer_role": role, "signer_service_id": service_id, "admission_request_sha256": digest, "issuer_id": f"issuer-{role.lower()}", "key_id": f"key-{role.lower()}", "issued_at": "2026-08-27T11:30:00Z", "valid_until": "2026-08-27T12:30:00Z"}
    jcs = rfc8785.dumps(grant); preimage = GRANT_DOMAIN + len(jcs).to_bytes(4, "little") + jcs
    envelope = {"schema": GRANT_SIGNATURE_SCHEMA, "version": 1, "algorithm": "ed25519", "issuer_id": grant["issuer_id"], "key_id": grant["key_id"], "signed_payload_sha256": hashlib.sha256(preimage).hexdigest(), "signature": bytes(key.sign_message(preimage)).hex()}
    raw = json.dumps({"unsigned_grant": grant, "signature_envelope": envelope}, separators=(",", ":")).encode()
    context = AdmissionGrantContext(role, service_id, "public-devnet", "a" * 40, "evidence-001", "b" * 32)
    issuer = AdmissionIssuerKeyV1(grant["key_id"], grant["issuer_id"], role, str(key.pubkey()), "2026-08-27T11:00:00Z", "2026-08-27T13:00:00Z")
    return base64.b64encode(raw).decode(), context, issuer


def _app(tmp_path, monkeypatch, *, grant_id="c" * 32):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    header, context, issuer = _grant(request, grant_id=grant_id)
    replay = AdmissionGrantReplayJournal(tmp_path / "admission.sqlite", signer_role="A")
    admission = SignerAdmissionRuntime(context, [issuer], replay, lambda: NOW)
    app = TestClient(create_independent_signer_service(engine=engine, service_config=engine._service_config, admission=admission, clock=lambda: 20))
    return app, request, journal, replay, vault, header


def test_grant_is_required_and_bearer_has_no_fallback(tmp_path, monkeypatch):
    client, request, journal, replay, vault, header = _app(tmp_path, monkeypatch)
    assert client.post("/v1/settlement-authorizations", json=request, headers={"Content-Type": "application/json", "Authorization": "Bearer old"}).status_code == 403
    assert client.post("/v1/settlement-authorizations", json=request, headers={"Content-Type": "application/json", "Authorization": "Bearer old", "X-Prophet-Admission-Grant": header[:-1] + "!"}).status_code == 403
    assert vault.sign_calls == 0
    journal.close(); replay.close()


def test_valid_grant_consumes_before_p0c1_and_replay_stops_engine(tmp_path, monkeypatch):
    client, request, journal, replay, vault, header = _app(tmp_path, monkeypatch)
    headers = {"Content-Type": "application/json", "X-Prophet-Admission-Grant": header}
    first = client.post("/v1/settlement-authorizations", json=request, headers=headers)
    second = client.post("/v1/settlement-authorizations", json=request, headers=headers)
    assert first.status_code == 200 and second.status_code == 403 and vault.sign_calls == 1
    journal.close(); replay.close()


def test_valid_grant_then_p0c1_failure_remains_consumed(tmp_path, monkeypatch):
    client, request, journal, replay, vault, header = _app(tmp_path, monkeypatch)
    request["cluster_genesis_hash"] = "00" * 32
    # Rebind the grant to the bad request: G1 succeeds, then P0C1 rejects.
    header, _, _ = _grant(request)
    headers = {"Content-Type": "application/json", "X-Prophet-Admission-Grant": header}
    assert client.post("/v1/settlement-authorizations", json=request, headers=headers).status_code == 422
    assert client.post("/v1/settlement-authorizations", json=request, headers=headers).status_code == 403
    assert vault.sign_calls == 0
    journal.close(); replay.close()
