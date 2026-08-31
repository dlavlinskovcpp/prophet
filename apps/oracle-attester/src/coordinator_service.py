"""Transport-only HTTP surface for the existing durable resolution coordinator."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from threading import Lock
from typing import Any, Mapping, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.requests import ClientDisconnect

from .resolution_coordinator import (
    ResolutionCoordinatorError,
    ResolutionCoordinatorPersistenceFailure,
    ResolutionCoordinatorVerifierFailure,
)
from .resolution_coordinator_store import (
    CoordinatorRejected,
    ResolutionJob,
    SettlementMessageContext,
    SettlementRuntimeBinding,
)
from .runtime_config import SolanaRuntimeConfig

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


logger = logging.getLogger("prophet.coordinator-service")


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


class CoordinatorServiceMetrics:
    def __init__(self) -> None:
        self._lock, self._rows = Lock(), defaultdict(float)

    def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None:
        with self._lock:
            self._rows[(name, tuple(sorted(labels.items())))] += value

    def observe(self, name: str, value: float, labels: Mapping[str, str]) -> None:
        with self._lock:
            self._rows[(f"{name}_sum", tuple(sorted(labels.items())))] += value
            self._rows[(f"{name}_count", tuple(sorted(labels.items())))] += 1

    def render(self) -> str:
        with self._lock:
            return "".join(
                f'{name}' + ("{" + ",".join(f'{key}="{value}"' for key, value in labels) + "}" if labels else "") + f" {value}\n"
                for (name, labels), value in sorted(self._rows.items())
            )


def _request_id(request: Request) -> str:
    candidate = request.headers.get("x-request-id", "")
    if candidate and len(candidate) <= 64 and all(char.isascii() and (char.isalnum() or char in "._-") for char in candidate):
        return candidate
    return uuid.uuid4().hex


def _authorized(request: Request, token: str) -> bool:
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    return bool(token and scheme.lower() == "bearer" and supplied and hmac.compare_digest(supplied, token))


def _result_summary(result: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    if result is None:
        return None
    verifier = result["verifier"]
    return {
        "result": result["result"],
        "definition_hash": result["definition_hash"],
        "evidence_hash": result["evidence_hash"],
        "verifier": {
            "adapter_id": verifier["adapter_id"],
            "adapter_version": verifier["adapter_version"],
            "implementation_digest": verifier["implementation_digest"],
        },
    }


def _job_payload(job: ResolutionJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "state": job.state,
        "resolver_definition_hash": job.resolver_definition_hash,
        "evidence_hash": job.evidence_hash,
        "verifier_a": _result_summary(job.verifier_a_result),
        "verifier_b": _result_summary(job.verifier_b_result),
        "outcome": job.outcome,
        "conflict_reason": job.conflict_reason,
        "created_at_ms": job.created_at_ms,
        "updated_at_ms": job.updated_at_ms,
    }


def _validate_request(
    payload: Any,
    *,
    solana_runtime: SolanaRuntimeConfig | None = None,
    require_settlement_context: bool = False,
) -> tuple[
    str,
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
    SettlementMessageContext | None,
    SettlementRuntimeBinding | None,
]:
    required = {"market", "resolver_definition", "evidence", "trust_model"}
    if require_settlement_context:
        required.add("settlement_context")
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("invalid_request_shape")
    market, definition, evidence, trust = payload["market"], payload["resolver_definition"], payload["evidence"], payload["trust_model"]
    if not isinstance(market, str) or len(market) != 64 or bytes.fromhex(market).hex() != market:
        raise ValueError("invalid_market")
    definition = resolver_v2.validate_resolver_definition(definition)
    evidence = resolver_v2.validate_evidence_envelope(evidence)
    trust = resolver_v2._validate_trust_model(trust)
    definition_hash = resolver_v2.resolver_definition_hash(definition).hex()
    if evidence["definition_hash"] != definition_hash or definition["trust_model"] != trust:
        raise ValueError("canonical_request_binding_mismatch")

    context = None
    runtime_binding = None
    if require_settlement_context:
        if not isinstance(solana_runtime, SolanaRuntimeConfig):
            raise ValueError("trusted_solana_runtime_required")
        row = payload["settlement_context"]
        keys = {
            "creator",
            "market_nonce",
            "notary_config",
            "open_ts",
            "resolve_ts",
            "notary_config_version",
            "proof_hash",
            "public_inputs_hash",
        }
        if not isinstance(row, dict) or set(row) != keys:
            raise ValueError("settlement_context_shape_invalid")
        context = SettlementMessageContext(
            program_id=solana_runtime.prophet_program_id,
            creator=row["creator"],
            market_nonce=row["market_nonce"],
            notary_config=row["notary_config"],
            open_ts=row["open_ts"],
            resolve_ts=row["resolve_ts"],
            notary_config_version=row["notary_config_version"],
            proof_hash=row["proof_hash"],
            public_inputs_hash=row["public_inputs_hash"],
        )
        runtime_binding = SettlementRuntimeBinding(
            cluster=solana_runtime.cluster,
            genesis_hash=solana_runtime.genesis_hash,
            program_id=solana_runtime.prophet_program_id,
        )
    return market, definition, evidence, trust, context, runtime_binding


def create_coordinator_service(
    *,
    coordinator: Any = None,
    state: Any = None,
    auth_token: str = "",
    request_max_bytes: int,
    request_timeout_seconds: int,
    startup_error: Optional[str] = None,
    close_resources: bool = False,
    solana_runtime: SolanaRuntimeConfig | None = None,
    require_settlement_context: bool = False,
    settlement_executor: Any = None,
) -> FastAPI:
    """Create the HTTP layer; request handlers delegate only to coordinator APIs."""
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            if close_resources:
                for resource in (getattr(coordinator, "verifier_client_a", None), getattr(coordinator, "verifier_client_b", None), settlement_executor, state):
                    close = getattr(resource, "close", None)
                    if close is not None:
                        close()

    app = FastAPI(title="Prophet Resolution Coordinator", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    metrics = CoordinatorServiceMetrics()
    ready = coordinator is not None and state is not None and bool(auth_token) and startup_error is None
    if require_settlement_context and not isinstance(solana_runtime, SolanaRuntimeConfig):
        ready = False
    app.state.coordinator, app.state.state, app.state.ready = coordinator, state, ready
    app.state.metrics = metrics
    app.state.request_max_bytes, app.state.request_timeout_seconds = request_max_bytes, request_timeout_seconds
    app.state.solana_runtime = solana_runtime
    app.state.require_settlement_context = require_settlement_context
    app.state.settlement_executor = settlement_executor
    if coordinator is not None:
        logger.info(json.dumps({"event": "coordinator_service_startup", "ready": ready}, sort_keys=True))

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/ready")
    async def readiness():
        metrics.inc("coordinator_readiness", {"state": "ready" if app.state.ready else "not_ready"})
        return JSONResponse(status_code=200 if app.state.ready else 503, content={"ready": app.state.ready})

    @app.get("/metrics")
    async def metrics_endpoint():
        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.get("/v1/resolutions/{job_id}")
    async def get_resolution(job_id: str, request: Request):
        request_id = _request_id(request)
        if not app.state.ready:
            return JSONResponse(status_code=503, content={"error": "service_not_ready", "request_id": request_id})
        if not _authorized(request, auth_token):
            return JSONResponse(status_code=401, content={"error": "unauthorized", "request_id": request_id})
        try:
            job = app.state.state.get_job(job_id)
        except CoordinatorRejected:
            return JSONResponse(status_code=404, content={"error": "resolution_not_found", "request_id": request_id})
        response = JSONResponse(content=_job_payload(job))
        response.headers["X-Request-ID"] = request_id
        return response

    @app.post("/v1/resolve")
    async def resolve(request: Request):
        request_id, started = _request_id(request), time.perf_counter()
        status, category, state_name = 500, "internal", "unknown"
        metrics.inc("coordinator_inflight_requests", {"endpoint": "resolve"})
        try:
            if not app.state.ready:
                status, category = 503, "not_ready"
                return JSONResponse(status_code=status, content={"error": "service_not_ready", "request_id": request_id})
            if not _authorized(request, auth_token):
                status, category = 401, "unauthorized"
                return JSONResponse(status_code=status, content={"error": "unauthorized", "request_id": request_id})
            try:
                body = await _read_bounded_body(request, app.state.request_max_bytes)
            except _RequestTooLarge:
                status, category = 413, "too_large"
                return JSONResponse(status_code=status, content={"error": "request_too_large", "request_id": request_id})
            except ValueError:
                status, category = 400, "malformed"
                return JSONResponse(status_code=status, content={"error": "invalid_request", "request_id": request_id})
            try:
                parsed = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                status, category = 400, "malformed"
                return JSONResponse(status_code=status, content={"error": "invalid_json", "request_id": request_id})
            try:
                market, definition, evidence, trust, settlement_context, settlement_runtime = _validate_request(
                    parsed,
                    solana_runtime=app.state.solana_runtime,
                    require_settlement_context=app.state.require_settlement_context,
                )
            except (ValueError, TypeError, resolver_v2.ResolverV2Error, CoordinatorRejected):
                status, category = 422, "invalid_request"
                return JSONResponse(status_code=status, content={"error": "invalid_canonical_request", "request_id": request_id})
            try:
                job = await asyncio.wait_for(
                    asyncio.to_thread(
                        app.state.coordinator.resolve,
                        market=market,
                        resolver_definition=definition,
                        evidence=evidence,
                        trust_model=trust,
                        correlation_id=request_id,
                        settlement_context=settlement_context,
                        settlement_runtime=settlement_runtime,
                    ),
                    timeout=app.state.request_timeout_seconds,
                )
            except asyncio.TimeoutError:
                status, category = 503, "timeout"
                return JSONResponse(status_code=status, content={"error": "coordinator_timeout", "request_id": request_id})
            except ResolutionCoordinatorVerifierFailure:
                status, category = 503, "verifier_dependency"
                return JSONResponse(status_code=status, content={"error": "verifier_dependency_unavailable", "request_id": request_id})
            except ResolutionCoordinatorPersistenceFailure:
                status, category = 500, "persistence"
                return JSONResponse(status_code=status, content={"error": "coordinator_persistence_failure", "request_id": request_id})
            except ResolutionCoordinatorError:
                status, category = 500, "coordinator"
                return JSONResponse(status_code=status, content={"error": "coordinator_failure", "request_id": request_id})
            if job.state == "AGREED" and app.state.settlement_executor is not None:
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(
                            app.state.settlement_executor.execute,
                            job,
                            attestation_a=getattr(app.state.coordinator.verifier_client_a, "last_attestation", None),
                            attestation_b=getattr(app.state.coordinator.verifier_client_b, "last_attestation", None),
                        ),
                        timeout=app.state.request_timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    status, category = 503, "settlement_timeout"
                    return JSONResponse(status_code=status, content={"error": "settlement_timeout", "request_id": request_id})
                except Exception:
                    status, category = 503, "settlement_dependency"
                    return JSONResponse(status_code=status, content={"error": "settlement_unavailable", "request_id": request_id})
            status, category, state_name = 200, "resolved", job.state
            metrics.inc("coordinator_resolve_total", {"state": state_name})
            response = JSONResponse(content=_job_payload(job))
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception:
            status, category = 500, "internal"
            return JSONResponse(status_code=status, content={"error": "coordinator_internal_failure", "request_id": request_id})
        finally:
            metrics.inc("coordinator_inflight_requests", {"endpoint": "resolve"}, value=-1.0)
            metrics.inc("coordinator_http_requests_total", {"endpoint": "resolve", "status": str(status)})
            if status >= 500:
                metrics.inc("coordinator_resolve_failures_total", {"category": category})
            metrics.inc("coordinator_job_state_total", {"state": state_name})
            metrics.observe("coordinator_request_duration_seconds", time.perf_counter() - started, {"endpoint": "resolve"})
            logger.info(json.dumps({"event": "coordinator_request", "request_id": request_id, "endpoint": "resolve", "category": category, "state": state_name, "latency_ms": int((time.perf_counter() - started) * 1000)}, sort_keys=True))

    return app
