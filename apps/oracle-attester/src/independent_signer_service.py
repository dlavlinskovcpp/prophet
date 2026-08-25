"""Authenticated HTTP admission for one pre-constructed independent signer.

This module owns only transport framing and local service admission.  It never
authorizes settlement fields, accesses the journal directly, or signs bytes.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import time
from collections.abc import Callable, Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

from .independent_signer_execution import (
    IndependentSignerEngine,
    IndependentSignerExecutionError,
    IndependentSignerExecutionResult,
)
from .independent_signer_runtime import IndependentSignerServiceConfig
from .signer_authorization import SignerAuthorizationError


MAX_AUTHORIZATION_BODY_BYTES = 65_536


class IndependentSignerServiceStartupError(RuntimeError):
    """Raised when the local admission boundary is not safely configured."""


class _RequestTooLarge(ValueError):
    pass


class _RequestStreamFailure(ValueError):
    pass


def _admission_token(config: IndependentSignerServiceConfig) -> str:
    token = os.getenv(config.admission_token_env, "")
    if not isinstance(token, str) or not token:
        raise IndependentSignerServiceStartupError("independent_signer_admission_token_missing")
    return token


def _authorized(request: Request, token: str) -> bool:
    headers = request.headers.getlist("authorization")
    if len(headers) != 1:
        return False
    scheme, separator, presented = headers[0].partition(" ")
    return bool(separator and scheme.lower() == "bearer" and presented and hmac.compare_digest(presented, token))


def _json_content_type(request: Request) -> bool:
    value = request.headers.get("content-type", "")
    sections = [section.strip() for section in value.split(";")]
    if not sections or sections[0].lower() != "application/json":
        return False
    for parameter in sections[1:]:
        name, separator, raw_value = parameter.partition("=")
        if not separator or name.strip().lower() != "charset" or raw_value.strip().strip('"').lower() not in {"utf-8", "utf8"}:
            return False
    return True


async def _read_bounded_body(request: Request, maximum: int) -> bytes:
    values = [
        value for name, value in request.scope.get("headers", ())
        if isinstance(name, bytes) and name.lower() == b"content-length"
    ]
    if len(values) > 1:
        raise ValueError("content_length_duplicate")
    if values:
        raw = values[0]
        if not isinstance(raw, bytes) or not raw or len(raw) > 20:
            raise ValueError("content_length_invalid")
        try:
            declared = raw.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("content_length_invalid") from exc
        if (not declared.isdecimal() or (len(declared) > 1 and declared[0] == "0")):
            raise ValueError("content_length_invalid")
        if int(declared) > maximum:
            raise _RequestTooLarge("content_length_exceeds_limit")
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > maximum:
                raise _RequestTooLarge("streamed_body_exceeds_limit")
            body.extend(chunk)
    except _RequestTooLarge:
        raise
    except ClientDisconnect as exc:
        raise _RequestStreamFailure("stream_disconnected") from exc
    except Exception as exc:
        raise _RequestStreamFailure("stream_unavailable") from exc
    return bytes(body)


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _decode_request(body: bytes) -> Mapping[str, Any]:
    try:
        text = body.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("json_constant_invalid")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ValueError("json_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("json_top_level_object_required")
    return value


def _local_now(clock: Callable[[], Any]) -> int:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("local_clock_invalid")
    return value


def _result_payload(result: IndependentSignerExecutionResult) -> dict[str, str | int]:
    return {
        "schema": "PROPHET_SIGNER_SIGNATURE_V1",
        "version": "1",
        "signer_role": result.signer_role,
        "signer_id": result.signer_id,
        "public_key": result.public_key,
        "key_version": result.key_version,
        "scope_id": result.scope_id,
        "settlement_authorization_job_id": result.settlement_authorization_job_id,
        "canonical_message_digest": result.canonical_message_digest,
        "operation_id": result.operation_id,
        "signature": base64.b64encode(result.signature).decode("ascii"),
        "state": result.state,
    }


def create_independent_signer_service(
    *,
    engine: IndependentSignerEngine,
    service_config: IndependentSignerServiceConfig,
    clock: Callable[[], Any] | None = None,
) -> FastAPI:
    """Wrap exactly one P0C3B engine with strict local HTTP admission."""
    if not isinstance(engine, IndependentSignerEngine):
        raise IndependentSignerServiceStartupError("independent_signer_engine_required")
    if not isinstance(service_config, IndependentSignerServiceConfig):
        raise IndependentSignerServiceStartupError("independent_signer_service_config_required")
    if getattr(engine, "_service_config", None) != service_config:
        raise IndependentSignerServiceStartupError("independent_signer_service_config_binding_mismatch")
    token = _admission_token(service_config)
    local_clock = clock or (lambda: int(time.time() * 1000))

    app = FastAPI(
        title="Prophet Independent Signer",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.engine = engine
    app.state.ready = True

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/ready")
    async def ready() -> JSONResponse:
        return JSONResponse(status_code=200, content={"ready": True})

    @app.post("/v1/settlement-authorizations")
    async def sign_authorization(request: Request) -> JSONResponse:
        # Authentication intentionally precedes any request-body operation.
        if not _authorized(request, token):
            return JSONResponse(status_code=401, content={"error": "unauthorized"})
        if not _json_content_type(request):
            return JSONResponse(status_code=415, content={"error": "unsupported_media_type"})
        try:
            body = await _read_bounded_body(request, MAX_AUTHORIZATION_BODY_BYTES)
        except _RequestTooLarge:
            return JSONResponse(status_code=413, content={"error": "request_too_large"})
        except _RequestStreamFailure:
            return JSONResponse(status_code=400, content={"error": "invalid_request"})
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "invalid_request"})
        try:
            parsed = _decode_request(body)
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "invalid_request"})
        try:
            now_ms = _local_now(local_clock)
        except ValueError:
            return JSONResponse(status_code=503, content={"error": "service_unavailable"})
        try:
            result = engine.execute(parsed, now_ms=now_ms)
        except SignerAuthorizationError:
            return JSONResponse(status_code=422, content={"error": "authorization_rejected"})
        except IndependentSignerExecutionError:
            return JSONResponse(status_code=409, content={"error": "signing_not_completed"})
        except Exception:
            return JSONResponse(status_code=503, content={"error": "service_unavailable"})
        if not isinstance(result, IndependentSignerExecutionResult) or result.state != "SIGNED":
            return JSONResponse(status_code=409, content={"error": "signing_not_completed"})
        return JSONResponse(status_code=200, content=_result_payload(result))

    return app
