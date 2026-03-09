import hmac
import json
import logging
import os
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Any, Deque, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .audit import JsonlAuditLogger
from .config import settings
from .resolver import ResolverDefinition, compute_resolver_hash


def _validate_runtime() -> None:
    settings.validate_resolver_registry_service_runtime()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("resolver-registry")

_validate_runtime()


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

    def _key(self, name: str, labels: Optional[Dict[str, str]] = None):
        return (name, tuple(sorted((labels or {}).items())))

    def inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        with self._lock:
            self._counters[self._key(name, labels)] += value

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


def _canonicalize_resolver(payload: Dict[str, Any]) -> Dict[str, Any]:
    resolver = ResolverDefinition(**payload)
    return resolver.model_dump(mode="json")


def _hash_path(hash_hex: str) -> Path:
    if len(hash_hex) != 64 or any(ch not in "0123456789abcdef" for ch in hash_hex):
        raise ValueError("resolver hash must be a 64-char lowercase hex string")
    return Path(settings.RESOLVER_STORE_DIR) / f"{hash_hex}.json"


def _write_canonical_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.stem}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(canonical)
        handle.flush()
        os.fsync(handle.fileno())
        temp_path = Path(handle.name)

    os.replace(temp_path, path)


def _load_resolver_payload(hash_hex: str) -> Dict[str, Any]:
    path = _hash_path(hash_hex)
    if not path.exists():
        raise FileNotFoundError(hash_hex)

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    canonical = _canonicalize_resolver(payload)
    computed = compute_resolver_hash(canonical).hex()
    if computed != hash_hex:
        raise ValueError(f"resolver store integrity check failed for {hash_hex}")
    return canonical


def _list_resolvers(limit: int) -> List[Dict[str, Any]]:
    store = Path(settings.RESOLVER_STORE_DIR)
    if not store.exists():
        return []

    items: List[Dict[str, Any]] = []
    for path in sorted(store.glob("*.json")):
        stat = path.stat()
        items.append(
            {
                "resolver_hash": path.stem,
                "path": str(path),
                "updated_at": int(stat.st_mtime),
                "size_bytes": stat.st_size,
            }
        )
        if len(items) >= limit:
            break
    return items


metrics = MetricsRegistry()
rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.RATE_LIMIT_MAX_REQUESTS,
    window_s=settings.RATE_LIMIT_WINDOW_S,
)
audit_log = JsonlAuditLogger(settings.RESOLVER_REGISTRY_AUDIT_LOG_PATH, "resolver-registry")
app = FastAPI(title="Prophet Resolver Registry")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method
    status_code = 500

    try:
        if path.startswith("/resolvers"):
            if method in {"POST", "PUT"}:
                cl = request.headers.get("content-length")
                if cl:
                    try:
                        cl_val = int(cl)
                    except ValueError:
                        cl_val = settings.RESOLVER_REGISTRY_MAX_REQUEST_BYTES + 1
                else:
                    cl_val = 0

                if cl_val > settings.RESOLVER_REGISTRY_MAX_REQUEST_BYTES:
                    metrics.inc(
                        "prophet_resolver_registry_request_rejected_total",
                        labels={"reason": "payload_too_large"},
                    )
                    status_code = 413
                    return JSONResponse(status_code=413, content={"detail": "Payload too large"})

            token = ""
            if settings.RESOLVER_REGISTRY_REQUIRE_AUTH:
                token = _extract_bearer_token(request.headers.get("authorization", ""))
                if not token or not hmac.compare_digest(token, settings.RESOLVER_REGISTRY_SERVICE_API_KEY):
                    metrics.inc("prophet_resolver_registry_auth_failures_total")
                    status_code = 401
                    return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

            if settings.RATE_LIMIT_ENABLED:
                key_suffix = token[:12] if token else "anon"
                key = f"{_client_ip(request)}:{key_suffix}"
                allowed, retry_after = rate_limiter.allow(key)
                if not allowed:
                    metrics.inc("prophet_resolver_registry_rate_limited_total")
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
        if settings.METRICS_ENABLED:
            metrics.inc(
                "prophet_resolver_registry_http_requests_total",
                labels={"path": path, "method": method, "status": str(status_code)},
            )


@app.get("/health")
def health():
    store_dir = Path(settings.RESOLVER_STORE_DIR)
    return {
        "ok": True,
        "store_dir": str(store_dir),
        "resolver_count": len(list(store_dir.glob("*.json"))) if store_dir.exists() else 0,
        "audit_log_path": settings.RESOLVER_REGISTRY_AUDIT_LOG_PATH,
        "require_auth": settings.RESOLVER_REGISTRY_REQUIRE_AUTH,
        "max_request_bytes": settings.RESOLVER_REGISTRY_MAX_REQUEST_BYTES,
    }


@app.get("/metrics")
def metrics_endpoint():
    if not settings.METRICS_ENABLED:
        return PlainTextResponse("", media_type="text/plain; version=0.0.4")
    return PlainTextResponse(metrics.render_prometheus(), media_type="text/plain; version=0.0.4")


@app.get("/resolvers")
def list_resolvers(limit: int = Query(default=100, ge=1, le=1000)):
    items = _list_resolvers(limit)
    return {
        "resolvers": items,
        "count": len(items),
    }


@app.get("/resolvers/{resolver_hash}.json")
def get_resolver(resolver_hash: str):
    try:
        resolver = _load_resolver_payload(resolver_hash)
    except FileNotFoundError:
        metrics.inc("prophet_resolver_registry_get_total", labels={"result": "not_found"})
        raise HTTPException(status_code=404, detail="Resolver not found")
    except ValueError as exc:
        metrics.inc("prophet_resolver_registry_get_total", labels={"result": "invalid"})
        raise HTTPException(status_code=400, detail=str(exc))

    metrics.inc("prophet_resolver_registry_get_total", labels={"result": "success"})
    return {"resolver_hash": resolver_hash, "resolver": resolver}


@app.post("/resolvers")
async def publish_resolver(request: Request):
    try:
        body = await request.json()
    except Exception:
        metrics.inc("prophet_resolver_registry_publish_total", labels={"result": "bad_json"})
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(body, dict):
        metrics.inc("prophet_resolver_registry_publish_total", labels={"result": "bad_payload"})
        raise HTTPException(status_code=400, detail="Resolver payload must be a JSON object")

    resolver_payload = body.get("resolver", body)
    expected_hash = str(body.get("expected_hash", "")).strip().lower()
    metadata = body.get("metadata", {})
    if not isinstance(resolver_payload, dict):
        metrics.inc("prophet_resolver_registry_publish_total", labels={"result": "bad_payload"})
        raise HTTPException(status_code=400, detail="resolver must be a JSON object")
    if metadata and not isinstance(metadata, dict):
        metrics.inc("prophet_resolver_registry_publish_total", labels={"result": "bad_metadata"})
        raise HTTPException(status_code=400, detail="metadata must be a JSON object")

    try:
        resolver = _canonicalize_resolver(resolver_payload)
    except Exception as exc:
        metrics.inc("prophet_resolver_registry_publish_total", labels={"result": "validation_error"})
        raise HTTPException(status_code=400, detail=f"Invalid resolver definition: {exc}")

    resolver_hash = compute_resolver_hash(resolver).hex()
    if expected_hash and expected_hash != resolver_hash:
        metrics.inc("prophet_resolver_registry_publish_total", labels={"result": "hash_mismatch"})
        raise HTTPException(status_code=409, detail="expected_hash does not match canonical resolver hash")

    path = _hash_path(resolver_hash)
    created = not path.exists()

    if created:
        _write_canonical_json(path, resolver)
        logger.info("Published resolver %s", resolver_hash)
    else:
        existing = _load_resolver_payload(resolver_hash)
        if existing != resolver:
            metrics.inc("prophet_resolver_registry_publish_total", labels={"result": "integrity_error"})
            raise HTTPException(status_code=500, detail="resolver store integrity mismatch")

    audit_log.write(
        "resolver_published",
        {
            "resolver_hash": resolver_hash,
            "created": created,
            "client_ip": _client_ip(request),
            "metadata": metadata,
        },
    )
    metrics.inc(
        "prophet_resolver_registry_publish_total",
        labels={"result": "created" if created else "existing"},
    )
    return {
        "resolver_hash": resolver_hash,
        "created": created,
        "path": str(path),
    }
