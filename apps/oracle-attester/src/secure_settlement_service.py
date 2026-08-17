"""HTTP boundary for durable AGREED -> 2/2 -> simulate -> submit settlement.

The only protocol-significant caller input is a durable coordinator job id.
Canonical settlement fields and signatures are never accepted from HTTP.
"""
from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Iterable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .agreed_settlement_signer import (
    AgreedSettlementSigningError,
    CoordinatorJobMissing,
)
from .settlement_submission import SettlementSubmissionError


@dataclass(frozen=True)
class SecureSettlementResult:
    coordinator_job_id: str
    signing_intent_id: str
    canonical_message_digest: str
    transaction_attempt_id: str
    transaction_signature: str
    submission_state: str
    confirmation_status: str | None
    slot: int | None


class SecureSettlementEngine:
    def __init__(self, *, agreed_signer: Any, submission_service: Any) -> None:
        self._agreed_signer = agreed_signer
        self._submission = submission_service

    def settle(self, coordinator_job_id: str) -> SecureSettlementResult:
        signed = self._agreed_signer.sign_agreed_job(coordinator_job_id)
        submitted = self._submission.submit_settlement(coordinator_job_id)
        if submitted.signing_intent_id != signed.signing_intent_id:
            raise SettlementSubmissionError("settlement_signing_intent_binding_mismatch")
        return SecureSettlementResult(
            coordinator_job_id=coordinator_job_id,
            signing_intent_id=signed.signing_intent_id,
            canonical_message_digest=signed.canonical_message_digest,
            transaction_attempt_id=submitted.transaction_attempt_id,
            transaction_signature=submitted.transaction_signature,
            submission_state=submitted.submission_state,
            confirmation_status=submitted.confirmation_status,
            slot=submitted.slot,
        )


def _authorized(request: Request, token: str) -> bool:
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    return bool(
        token
        and scheme.lower() == "bearer"
        and supplied
        and hmac.compare_digest(supplied, token)
    )


def _valid_job_id(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def create_secure_settlement_service(
    *,
    engine: SecureSettlementEngine | None = None,
    auth_token: str = "",
    startup_error: str | None = None,
    close_resources: Iterable[Any] = (),
) -> FastAPI:
    resources = tuple(close_resources)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            for resource in reversed(resources):
                close = getattr(resource, "close", None)
                if close is not None:
                    close()

    app = FastAPI(
        title="Prophet Secure Settlement",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.ready = engine is not None and bool(auth_token) and startup_error is None
    app.state.engine = engine

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/ready")
    async def ready():
        return JSONResponse(
            status_code=200 if app.state.ready else 503,
            content={"ready": app.state.ready},
        )

    @app.post("/v1/settlements/{coordinator_job_id}/submit")
    async def submit(coordinator_job_id: str, request: Request):
        if not app.state.ready:
            return JSONResponse(status_code=503, content={"error": "service_not_ready"})
        if not _authorized(request, auth_token):
            return JSONResponse(status_code=401, content={"error": "unauthorized"})
        if not _valid_job_id(coordinator_job_id):
            return JSONResponse(status_code=404, content={"error": "resolution_not_found"})
        body = (await request.body()).strip()
        if body not in {b"", b"{}"}:
            return JSONResponse(
                status_code=400,
                content={"error": "settlement_request_must_not_contain_signed_fields"},
            )
        try:
            result = app.state.engine.settle(coordinator_job_id)
        except CoordinatorJobMissing:
            return JSONResponse(status_code=404, content={"error": "resolution_not_found"})
        except AgreedSettlementSigningError:
            return JSONResponse(status_code=409, content={"error": "resolution_not_signable"})
        except SettlementSubmissionError:
            return JSONResponse(status_code=409, content={"error": "settlement_not_submittable"})
        return {
            "coordinator_job_id": result.coordinator_job_id,
            "signing_intent_id": result.signing_intent_id,
            "canonical_message_digest": result.canonical_message_digest,
            "transaction_attempt_id": result.transaction_attempt_id,
            "transaction_signature": result.transaction_signature,
            "submission_state": result.submission_state,
            "confirmation_status": result.confirmation_status,
            "slot": result.slot,
        }

    return app
