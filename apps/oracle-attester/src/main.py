import hmac
import logging
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from .config import settings
from .types import ResolveRequest, ResolveResponse


def _validate_runtime() -> None:
    settings.validate_runtime()

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("oracle-attester")

_validate_runtime()

from .attester import service

app = FastAPI(title="Prophet Oracle Attester")


def _format_labels(labels: Dict[str, str]) -> str:
    if not labels:
        return ""
    parts = []
    for k, v in sorted(labels.items()):
        safe = str(v).replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'{k}="{safe}"')
    return "{" + ",".join(parts) + "}"


class MetricsRegistry:
    def __init__(self):
        self._lock = Lock()
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = defaultdict(float)
        self._bucket_bounds = [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]

    def _key(self, name: str, labels: Optional[Dict[str, str]] = None):
        return (name, tuple(sorted((labels or {}).items())))

    def inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        with self._lock:
            self._counters[self._key(name, labels)] += value

    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        labels = dict(labels or {})
        with self._lock:
            self._counters[self._key(f"{name}_sum", labels)] += value
            self._counters[self._key(f"{name}_count", labels)] += 1.0
            for bound in self._bucket_bounds:
                if value <= bound:
                    with_le = dict(labels)
                    with_le["le"] = str(bound)
                    self._counters[self._key(f"{name}_bucket", with_le)] += 1.0
            with_inf = dict(labels)
            with_inf["le"] = "+Inf"
            self._counters[self._key(f"{name}_bucket", with_inf)] += 1.0

    def render_prometheus(self) -> str:
        with self._lock:
            rows = []
            for (name, labels), value in sorted(self._counters.items(), key=lambda kv: (kv[0][0], kv[0][1])):
                rows.append(f"{name}{_format_labels(dict(labels))} {value}")
            return "\n".join(rows) + ("\n" if rows else "")


class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int, window_s: int):
        self.max_requests = max_requests
        self.window_s = window_s
        self._lock = Lock()
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> Tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - float(self.window_s)

        with self._lock:
            q = self._hits[key]
            while q and q[0] <= cutoff:
                q.popleft()

            if len(q) >= self.max_requests:
                retry_after = max(1, int(q[0] + self.window_s - now))
                return False, retry_after

            q.append(now)
            return True, 0


metrics = MetricsRegistry()
rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.RATE_LIMIT_MAX_REQUESTS,
    window_s=settings.RATE_LIMIT_WINDOW_S,
)


def _extract_bearer_token(auth_header: str) -> str:
    if not auth_header:
        return ""
    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def _client_ip(request: Request) -> str:
    if settings.RATE_LIMIT_TRUST_X_FORWARDED_FOR:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@app.middleware("http")
async def security_and_metrics_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method
    start = time.perf_counter()
    status_code = 500

    try:
        if path == "/resolve":
            cl = request.headers.get("content-length")
            if cl:
                try:
                    cl_val = int(cl)
                except ValueError:
                    cl_val = settings.MAX_REQUEST_BYTES + 1
            else:
                cl_val = 0

            if cl_val > settings.MAX_REQUEST_BYTES:
                metrics.inc("prophet_attester_request_rejected_total", labels={"reason": "payload_too_large"})
                status_code = 413
                return JSONResponse(status_code=413, content={"detail": "Payload too large"})

            token = ""
            if settings.REQUIRE_API_AUTH:
                token = _extract_bearer_token(request.headers.get("authorization", ""))
                if not token or not hmac.compare_digest(token, settings.API_AUTH_TOKEN):
                    metrics.inc("prophet_attester_auth_failures_total")
                    status_code = 401
                    return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

            if settings.RATE_LIMIT_ENABLED:
                key_suffix = token[:12] if token else "anon"
                key = f"{_client_ip(request)}:{key_suffix}"
                allowed, retry_after = rate_limiter.allow(key)
                if not allowed:
                    metrics.inc("prophet_attester_rate_limited_total")
                    status_code = 429
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Rate limit exceeded"},
                        headers={"Retry-After": str(retry_after)},
                    )

        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        elapsed = max(0.0, time.perf_counter() - start)
        if settings.METRICS_ENABLED:
            labels = {"path": path, "method": method, "status": str(status_code)}
            metrics.inc("prophet_attester_http_requests_total", labels=labels)
            metrics.observe_histogram(
                "prophet_attester_http_request_duration_seconds",
                elapsed,
                labels={"path": path, "method": method},
            )

@app.get("/health")
def health_check():
    return {
        "ok": True,
        "zktls_mode": settings.ZKTLS_MODE,
        "require_zktls": settings.REQUIRE_ZKTLS,
        "app_env": settings.APP_ENV,
        "allow_legacy_single_oracle": settings.ALLOW_LEGACY_SINGLE_ORACLE,
    }


@app.get("/metrics")
def metrics_endpoint():
    if not settings.METRICS_ENABLED:
        return PlainTextResponse("", media_type="text/plain; version=0.0.4")
    return PlainTextResponse(metrics.render_prometheus(), media_type="text/plain; version=0.0.4")


@app.post("/resolve", response_model=ResolveResponse)
async def resolve_market_endpoint(req: ResolveRequest):
    logger.info(f"Request: Resolve {req.market} -> {req.outcome}")
    try:
        resp = await service.resolve_market(req)
        logger.info(f"Success: {req.market} resolved in tx {resp.signature}")
        metrics.inc("prophet_attester_resolve_total", labels={"result": "success"})
        return resp
    except LookupError as e:
        logger.warning(f"Not Found: {e}")
        metrics.inc("prophet_attester_resolve_total", labels={"result": "not_found"})
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        logger.warning(f"Forbidden: {e}")
        metrics.inc("prophet_attester_resolve_total", labels={"result": "forbidden"})
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        logger.warning(f"Conflict: {e}")
        # 409 Conflict covers "already resolved" or "too early" or "in flight"
        metrics.inc("prophet_attester_resolve_total", labels={"result": "conflict"})
        raise HTTPException(status_code=409, detail=str(e))
    except RuntimeError as e:
        logger.error(f"Tx Failed: {e}")
        metrics.inc("prophet_attester_resolve_total", labels={"result": "runtime_error"})
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception(f"Internal Error: {e}")
        metrics.inc("prophet_attester_resolve_total", labels={"result": "internal_error"})
        raise HTTPException(status_code=500, detail="Internal Server Error")
