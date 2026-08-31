"""Authenticated HTTP admission for one pre-constructed independent signer.

This module owns only transport framing and local service admission.  It never
authorizes settlement fields, accesses the journal directly, or signs bytes.
"""
from __future__ import annotations

import base64
import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
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
from .signer_admission_grant import AdmissionGrantError, StrictSignerAuthorizationRequestV1, decode_strict_json
from .signer_admission_runtime import SignerAdmissionRuntime, SignerAdmissionRuntimeError, decode_grant_header
from .signer_authorization import SignerAuthorizationError


MAX_AUTHORIZATION_BODY_BYTES = 65_536


class IndependentSignerServiceStartupError(RuntimeError):
    """Raised when the local admission boundary is not safely configured."""


class _RequestTooLarge(ValueError):
    pass


class _RequestStreamFailure(ValueError):
    pass


class _AuthorizationConcurrency:
    def __init__(self, maximum: int) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0 or maximum > 1024:
            raise IndependentSignerServiceStartupError("signer_authorization_concurrency_invalid")
        self.maximum = maximum
        self._active = 0
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self._lock:
            if self._active >= self.maximum:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)


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


def _decode_request(body: bytes) -> Mapping[str, Any]:
    """Strictly decode transport JSON; P0C1 immediately makes it typed."""
    try:
        value = decode_strict_json(body)
    except AdmissionGrantError as exc:
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
    admission: SignerAdmissionRuntime,
    clock: Callable[[], Any] | None = None,
) -> FastAPI:
    """Wrap exactly one P0C3B engine with strict local HTTP admission."""
    if not isinstance(engine, IndependentSignerEngine):
        raise IndependentSignerServiceStartupError("independent_signer_engine_required")
    if not isinstance(service_config, IndependentSignerServiceConfig):
        raise IndependentSignerServiceStartupError("independent_signer_service_config_required")
    if getattr(engine, "_service_config", None) != service_config:
        raise IndependentSignerServiceStartupError("independent_signer_service_config_binding_mismatch")
    if not isinstance(admission, SignerAdmissionRuntime):
        raise IndependentSignerServiceStartupError("independent_signer_admission_runtime_required")
    if admission.context.signer_role != service_config.signer_role or admission.context.signer_service_id != service_config.signer_id:
        raise IndependentSignerServiceStartupError("independent_signer_admission_context_binding_mismatch")
    local_clock = clock or (lambda: int(time.time() * 1000))
    try:
        max_inflight = int(os.getenv("SIGNER_MAX_INFLIGHT_AUTHORIZATIONS", "8"))
    except ValueError as exc:
        raise IndependentSignerServiceStartupError("signer_authorization_concurrency_invalid") from exc
    concurrency = _AuthorizationConcurrency(max_inflight)

    # The security engine owns synchronous RPC, Vault, SQLite, and signing
    # operations.  A single role-local worker keeps those operations off the
    # HTTP loop while preserving the journal's serialized anti-equivocation
    # boundary.  Admission and readiness use the same worker, so a connection
    # scoped SQLite transaction can never cross an arbitrary worker thread.
    worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"signer-{service_config.signer_role.lower()}")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            worker.shutdown(wait=True, cancel_futures=True)

    app = FastAPI(
        title="Prophet Independent Signer",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.engine = engine
    app.state.ready = False
    app.state.worker = worker

    def readiness() -> tuple[bool, str]:
        try:
            now = _local_now(local_clock)
        except ValueError:
            return False, "local_clock_invalid"
        if not admission.issuer_keys or admission.context.signer_role != service_config.signer_role:
            return False, "admission_unavailable"
        if not admission.replay_journal.health():
            return False, "replay_journal_unavailable"
        if not engine._journal.health():
            return False, "signing_journal_unavailable"
        try:
            if engine._rpc.genesis_hash() != service_config.expected_genesis_hash:
                return False, "rpc_identity_mismatch"
            slot = engine._rpc.finalized_slot()
            if not isinstance(slot, int) or isinstance(slot, bool) or slot < 0:
                return False, "rpc_unavailable"
            if engine._rpc.block_time(slot) is None:
                return False, "rpc_unavailable"
        except Exception:
            return False, "rpc_unavailable"
        try:
            identity = engine._vault.validate_identity()
            if identity.public_key != service_config.signer_public_key or identity.key_version != service_config.signer_key_version:
                return False, "vault_identity_mismatch"
        except Exception as exc:
            if "mismatch" in str(exc):
                return False, "vault_identity_mismatch"
            return False, "vault_unavailable"
        return True, ""

    app.state.readiness = readiness

    async def run_blocking(function: Callable[..., Any], *args: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(worker, lambda: function(*args))

    @app.get("/health")
    async def health() -> dict[str, bool | str]:
        ready_state, reason = await run_blocking(readiness)
        return {"ok": ready_state, "live": True, "ready": ready_state, **({"reason": reason} if reason else {})}

    @app.get("/live")
    async def live() -> dict[str, bool]:
        return {"live": True}

    @app.get("/ready")
    async def ready() -> JSONResponse:
        ready_state, reason = await run_blocking(readiness)
        if not ready_state:
            return JSONResponse(status_code=503, content={"ready": False, "reason": reason})
        return JSONResponse(status_code=200, content={"ready": True})

    @app.post("/v1/settlement-authorizations")
    async def sign_authorization(request: Request) -> JSONResponse:
        if not concurrency.try_acquire():
            return JSONResponse(status_code=503, content={"error": "authorization_capacity_exhausted"})
        try:
            return await _sign_authorization(request, admission=admission, engine=engine, local_clock=local_clock)
        finally:
            concurrency.release()

    async def _sign_authorization(request: Request, *, admission: SignerAdmissionRuntime, engine: IndependentSignerEngine, local_clock: Callable[[], Any]) -> JSONResponse:
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
            strict = StrictSignerAuthorizationRequestV1.from_mapping(parsed)
            headers = request.headers.getlist("x-prophet-admission-grant")
            if len(headers) != 1:
                raise SignerAdmissionRuntimeError("grant_transport_invalid")
            raw_grant = decode_grant_header(headers[0])
        except (AdmissionGrantError, SignerAdmissionRuntimeError):
            return JSONResponse(status_code=403, content={"error": "admission_rejected"})

        def admit_and_execute() -> IndependentSignerExecutionResult:
            admission.admit(request=strict, raw_grant=raw_grant)
            now_ms = _local_now(local_clock)
            return engine.execute(parsed, now_ms=now_ms)

        try:
            result = await run_blocking(admit_and_execute)
        except (AdmissionGrantError, SignerAdmissionRuntimeError):
            return JSONResponse(status_code=403, content={"error": "admission_rejected"})
        except SignerAuthorizationError:
            return JSONResponse(status_code=422, content={"error": "authorization_rejected"})
        except IndependentSignerExecutionError:
            return JSONResponse(status_code=409, content={"error": "signing_not_completed"})
        except ValueError:
            return JSONResponse(status_code=503, content={"error": "service_unavailable"})
        except Exception:
            return JSONResponse(status_code=503, content={"error": "service_unavailable"})
        if not isinstance(result, IndependentSignerExecutionResult) or result.state != "SIGNED":
            return JSONResponse(status_code=409, content={"error": "signing_not_completed"})
        return JSONResponse(status_code=200, content=_result_payload(result))

    return app
