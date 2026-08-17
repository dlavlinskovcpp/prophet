import base64

from fastapi.testclient import TestClient

from src.agreed_settlement_signer import CoordinatorJobMissing
from src.secure_settlement_service import (
    SecureSettlementResult,
    create_secure_settlement_service,
)


JOB = "ab" * 32


class Engine:
    def __init__(self, *, missing=False):
        self.calls = []
        self.missing = missing

    def settle(self, job_id):
        self.calls.append(job_id)
        if self.missing:
            raise CoordinatorJobMissing("coordinator_job_missing")
        return SecureSettlementResult(
            coordinator_job_id=job_id,
            signing_intent_id="cd" * 32,
            canonical_message_digest="ef" * 32,
            transaction_attempt_id="attempt-1",
            transaction_signature="tx-1",
            submission_state="CONFIRMED",
            confirmation_status="confirmed",
            slot=7,
        )


def _client(engine):
    return TestClient(
        create_secure_settlement_service(engine=engine, auth_token="api-token")
    )


def test_secure_settlement_api_accepts_only_coordinator_job_id():
    engine = Engine()
    response = _client(engine).post(
        f"/v1/settlements/{JOB}/submit",
        headers={"Authorization": "Bearer api-token"},
    )
    assert response.status_code == 200
    assert engine.calls == [JOB]
    payload = response.json()
    assert "signature_bundle" not in payload
    assert "signer_a_signature" not in payload
    assert "signer_b_signature" not in payload


def test_bearer_token_cannot_supply_arbitrary_canonical_or_agreed_fields():
    canonical = b"PROPHET_RESOLVE_V2" + bytes(235 - 18)
    forbidden = [
        {"message_b64": base64.b64encode(canonical).decode()},
        {"outcome": "YES"},
        {"market": "11" * 32},
        {"state": "AGREED"},
        {"signatures": ["caller-forged"]},
        {"public_key": "11111111111111111111111111111111"},
    ]
    for body in forbidden:
        engine = Engine()
        response = _client(engine).post(
            f"/v1/settlements/{JOB}/submit",
            headers={"Authorization": "Bearer api-token"},
            json=body,
        )
        assert response.status_code == 400
        assert engine.calls == []


def test_bearer_token_without_durable_job_cannot_create_signature():
    engine = Engine(missing=True)
    response = _client(engine).post(
        f"/v1/settlements/{JOB}/submit",
        headers={"Authorization": "Bearer api-token"},
    )
    assert response.status_code == 404
    assert engine.calls == [JOB]


def test_secure_settlement_api_requires_its_own_bearer_token():
    engine = Engine()
    response = _client(engine).post(f"/v1/settlements/{JOB}/submit")
    assert response.status_code == 401
    assert engine.calls == []
