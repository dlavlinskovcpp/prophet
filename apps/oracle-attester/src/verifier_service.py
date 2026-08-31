"""Thin HTTP transport for one already-constructed Resolver verifier runtime."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
import uuid
from collections import defaultdict
from threading import Lock
from typing import Any, Mapping, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.requests import ClientDisconnect

from .resolver_v2_pipeline import PipelineRejected


logger = logging.getLogger("prophet.verifier-service")


class _RequestTooLarge(ValueError):
    pass


async def _read_bounded_body(request: Request, maximum: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdecimal() or (len(declared) > 1 and declared.startswith("0"))):
        raise ValueError("content_length_invalid")
    if declared is not None and int(declared) > maximum:
        raise _RequestTooLarge("content_length_exceeds_limit")
    data = bytearray()
    try:
        async for chunk in request.stream():
            if len(data) + len(chunk) > maximum:
                raise _RequestTooLarge("streamed_body_exceeds_limit")
            data.extend(chunk)
    except _RequestTooLarge:
        raise
    except ClientDisconnect as exc:
        raise ValueError("request_stream_disconnected") from exc
    except Exception as exc:
        raise ValueError("request_stream_unavailable") from exc
    return bytes(data)


class VerifierServiceMetrics:
    def __init__(self): self._lock, self._rows = Lock(), defaultdict(float)
    def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0):
        with self._lock: self._rows[(name, tuple(sorted(labels.items())))] += value
    def observe(self, name: str, value: float, labels: Mapping[str, str]):
        with self._lock:
            self._rows[(f"{name}_sum", tuple(sorted(labels.items())))] += value
            self._rows[(f"{name}_count", tuple(sorted(labels.items())))] += 1
    def render(self) -> str:
        with self._lock:
            return "".join(f'{name}' + ("{" + ",".join(f'{key}="{value}"' for key, value in labels) + "}" if labels else "") + f" {value}\n" for (name, labels), value in sorted(self._rows.items()))


def _request_id(request: Request) -> str:
    supplied = request.headers.get("x-request-id", "")
    if supplied and len(supplied) <= 64 and all(char.isascii() and (char.isalnum() or char in "._-") for char in supplied):
        return supplied
    return uuid.uuid4().hex


def _authorized(request: Request, token: str) -> bool:
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    return bool(token and scheme.lower() == "bearer" and presented and hmac.compare_digest(presented, token))


def create_verifier_service(*, runtime: Any = None, auth_token: str = "", expected_verifier_id: str, expected_verifier_version: str, request_max_bytes: int, request_timeout_seconds: int, startup_error: Optional[str] = None) -> FastAPI:
    """Create one transport-only verifier service; no protocol logic lives here."""
    app = FastAPI(
        title=f"Prophet Verifier {expected_verifier_id}",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    metrics = VerifierServiceMetrics()
    ready = runtime is not None and bool(auth_token) and startup_error is None
    if ready:
        descriptor = dict(getattr(runtime, "verifier_descriptor", {}))
        ready = (descriptor.get("adapter_id"), descriptor.get("adapter_version")) == (expected_verifier_id, expected_verifier_version)
    app.state.runtime, app.state.ready, app.state.metrics = runtime, ready, metrics
    app.state.startup_error = startup_error
    app.state.expected_verifier_id = expected_verifier_id
    app.state.request_max_bytes, app.state.request_timeout_seconds = request_max_bytes, request_timeout_seconds
    if runtime is not None:
        config = getattr(runtime, "runtime_config", None)
        fingerprint = config.fingerprint() if config is not None else ""
        logger.info(json.dumps({"event": "verifier_service_startup", "verifier_id": expected_verifier_id, "verifier_version": expected_verifier_version, "runtime_fingerprint": fingerprint, "ready": ready}, sort_keys=True))

    @app.get("/health")
    async def health(): return {"ok": True}

    @app.get("/ready")
    async def readiness():
        metrics.inc("verifier_readiness", {"verifier": expected_verifier_id, "state": "ready" if app.state.ready else "not_ready"})
        return JSONResponse(status_code=200 if app.state.ready else 503, content={"ready": app.state.ready})

    @app.get("/metrics")
    async def metrics_endpoint(): return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.post("/v1/verify")
    async def verify(request: Request):
        request_id, started = _request_id(request), time.perf_counter()
        status, category, adapter = 500, "internal", "unknown"
        metrics.inc("verifier_inflight_requests", {"verifier": expected_verifier_id})
        try:
            if not app.state.ready: status, category = 503, "not_ready"; return JSONResponse(status_code=status, content={"error": "service_not_ready", "request_id": request_id})
            if not _authorized(request, auth_token): status, category = 401, "unauthorized"; return JSONResponse(status_code=status, content={"error": "unauthorized", "request_id": request_id})
            try:
                body = await _read_bounded_body(request, app.state.request_max_bytes)
            except _RequestTooLarge:
                status, category = 413, "too_large"; return JSONResponse(status_code=status, content={"error": "request_too_large", "request_id": request_id})
            except ValueError:
                status, category = 400, "malformed"; return JSONResponse(status_code=status, content={"error": "invalid_request", "request_id": request_id})
            try:
                payload = json.loads(body)
                allowed = {"resolver_definition", "evidence", "trust_model", "attestation_context"}
                if not isinstance(payload, dict) or not {"resolver_definition", "evidence", "trust_model"}.issubset(payload) or set(payload) - allowed: raise ValueError
                definition, evidence, trust_model = payload["resolver_definition"], payload["evidence"], payload["trust_model"]
                resolver_type = definition.get("resolver_type") if isinstance(definition, dict) else None
                adapter = resolver_type if resolver_type in {"zktls", "signed_oracle", "pyth", "chainlink"} else "unknown"
            except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
                status, category = 400, "malformed"; return JSONResponse(status_code=status, content={"error": "invalid_request", "request_id": request_id})
            try:
                if getattr(app.state.runtime, "attestation_signer", None) is not None:
                    if "attestation_context" not in payload:
                        raise PipelineRejected("attestation_context_required")
                    result = await asyncio.wait_for(asyncio.to_thread(app.state.runtime.verify_attested, resolver_definition=definition, evidence=evidence, trust_model=trust_model, attestation_context=payload["attestation_context"]), timeout=app.state.request_timeout_seconds)
                    status, category = 200, "verified"
                    response = JSONResponse(status_code=status, content=result); response.headers["X-Request-ID"] = request_id; return response
                result = await asyncio.wait_for(asyncio.to_thread(app.state.runtime.verify, resolver_definition=definition, evidence=evidence, trust_model=trust_model), timeout=app.state.request_timeout_seconds)
            except asyncio.TimeoutError:
                status, category = 503, "timeout"; return JSONResponse(status_code=status, content={"error": "verification_timeout", "request_id": request_id})
            except PipelineRejected:
                status, category = 422, "rejected"; return JSONResponse(status_code=status, content={"error": "verification_request_rejected", "request_id": request_id})
            status, category = 200, "verified" if result.get("result") == "VERIFIED" else "rejected_result"
            metrics.inc("verifier_verification_total", {"verifier": expected_verifier_id, "adapter": adapter, "result": category})
            if category != "verified": metrics.inc("verifier_verification_failures_total", {"verifier": expected_verifier_id, "adapter": adapter})
            response = JSONResponse(status_code=status, content=result); response.headers["X-Request-ID"] = request_id; return response
        except Exception:
            status, category = 503, "internal"; return JSONResponse(status_code=status, content={"error": "verification_unavailable", "request_id": request_id})
        finally:
            metrics.inc("verifier_inflight_requests", {"verifier": expected_verifier_id}, value=-1.0)
            metrics.inc("verifier_http_requests_total", {"verifier": expected_verifier_id, "endpoint": "verify", "status": str(status)})
            metrics.observe("verifier_request_duration_seconds", time.perf_counter() - started, {"verifier": expected_verifier_id, "endpoint": "verify"})
            logger.info(json.dumps({"event": "verifier_request", "request_id": request_id, "verifier_id": expected_verifier_id, "adapter": adapter, "category": category, "latency_ms": int((time.perf_counter() - started) * 1000)}, sort_keys=True))

    return app
