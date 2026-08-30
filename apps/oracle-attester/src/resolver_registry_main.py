import hashlib
import hmac
import ipaddress
import json
import logging
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Any, Deque, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .audit import JsonlAuditLogger
from .config import settings
from .durable_files import atomic_write_bytes
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
    def __init__(
        self,
        max_requests: int,
        window_s: int,
        *,
        max_identities: int = 10_000,
        clock=None,
        cleanup_interval_s: Optional[float] = None,
    ):
        if max_requests <= 0 or window_s <= 0 or max_identities <= 0:
            raise ValueError("rate-limiter limits must be positive")
        self.max_requests = max_requests
        self.window_s = window_s
        self.max_identities = max_identities
        self._clock = clock or time.monotonic
        self._cleanup_interval_s = (
            float(cleanup_interval_s)
            if cleanup_interval_s is not None
            else min(5.0, max(0.25, float(window_s) / 2.0))
        )
        if self._cleanup_interval_s <= 0:
            raise ValueError("cleanup_interval_s must be positive")
        self._next_cleanup_at = 0.0
        self._lock = Lock()
        self._hits: Dict[str, Deque[float]] = {}

    @property
    def identity_count(self) -> int:
        with self._lock:
            return len(self._hits)

    def _prune_queue(self, q: Deque[float], cutoff: float) -> None:
        while q and q[0] <= cutoff:
            q.popleft()

    def _cleanup_locked(self, now: float, cutoff: float) -> int:
        if now < self._next_cleanup_at:
            return 0
        removed = 0
        for key, q in list(self._hits.items()):
            self._prune_queue(q, cutoff)
            if not q:
                del self._hits[key]
                removed += 1
        self._next_cleanup_at = now + self._cleanup_interval_s
        return removed

    def allow(self, key: str) -> Tuple[bool, int]:
        now = self._clock()
        cutoff = now - float(self.window_s)

        with self._lock:
            self._cleanup_locked(now, cutoff)
            q = self._hits.get(key)
            if q is not None:
                self._prune_queue(q, cutoff)
                if not q:
                    del self._hits[key]
                    q = None

            if q is None:
                if len(self._hits) >= self.max_identities:
                    # Fail closed instead of evicting an active identity and
                    # weakening the configured per-identity request limit.
                    return False, max(1, int(self.window_s))
                q = deque()
                self._hits[key] = q

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


def _direct_client_identity(request: Request) -> str:
    if not request.client:
        return "unknown"
    host = str(request.client.host or "").strip()
    if not host:
        return "unknown"
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        # ASGI test clients and trusted local transports may expose a host
        # label rather than an IP. Bound it so attacker-controlled key strings
        # cannot grow without limit.
        return host[:128]


def _client_ip(request: Request) -> str:
    direct = _direct_client_identity(request)
    if not settings.RATE_LIMIT_TRUST_X_FORWARDED_FOR:
        return direct

    xff = request.headers.get("x-forwarded-for", "")
    if not xff:
        return direct
    candidate = xff.split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return direct


def _rate_limit_token_identity(token: str) -> str:
    if not token:
        return "anon"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


class RequestBodyTooLarge(ValueError):
    pass


async def _read_bounded_request_body(request: Request, max_bytes: int) -> bytes:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > max_bytes:
            raise RequestBodyTooLarge("request body exceeds configured size limit")
        data.extend(chunk)
    return bytes(data)


def _canonicalize_resolver(payload: Dict[str, Any]) -> Dict[str, Any]:
    resolver = ResolverDefinition(**payload)
    return resolver.model_dump(mode="json")


def _hash_path(hash_hex: str) -> Path:
    if len(hash_hex) != 64 or any(ch not in "0123456789abcdef" for ch in hash_hex):
        raise ValueError("resolver hash must be a 64-char lowercase hex string")
    return Path(settings.RESOLVER_STORE_DIR) / f"{hash_hex}.json"


def _write_canonical_json(path: Path, payload: Dict[str, Any]) -> None:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    atomic_write_bytes(path, canonical.encode("utf-8"))


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
    max_identities=settings.RATE_LIMIT_MAX_IDENTITIES,
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
                if cl is not None:
                    try:
                        cl_val = int(cl)
                    except ValueError:
                        metrics.inc(
                            "prophet_resolver_registry_request_rejected_total",
                            labels={"reason": "invalid_content_length"},
                        )
                        status_code = 400
                        return JSONResponse(
                            status_code=400,
                            content={"detail": "Invalid Content-Length"},
                        )
                    if cl_val < 0:
                        metrics.inc(
                            "prophet_resolver_registry_request_rejected_total",
                            labels={"reason": "invalid_content_length"},
                        )
                        status_code = 400
                        return JSONResponse(
                            status_code=400,
                            content={"detail": "Invalid Content-Length"},
                        )
                    if cl_val > settings.RESOLVER_REGISTRY_MAX_REQUEST_BYTES:
                        metrics.inc(
                            "prophet_resolver_registry_request_rejected_total",
                            labels={"reason": "payload_too_large"},
                        )
                        status_code = 413
                        return JSONResponse(
                            status_code=413,
                            content={"detail": "Payload too large"},
                        )

            token = ""
            if settings.RESOLVER_REGISTRY_REQUIRE_AUTH:
                token = _extract_bearer_token(request.headers.get("authorization", ""))
                if not token or not hmac.compare_digest(token, settings.RESOLVER_REGISTRY_SERVICE_API_KEY):
                    metrics.inc("prophet_resolver_registry_auth_failures_total")
                    status_code = 401
                    return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

            if settings.RATE_LIMIT_ENABLED:
                key = (
                    f"{_client_ip(request)}:"
                    f"{_rate_limit_token_identity(token)}"
                )
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
        raw_body = await _read_bounded_request_body(
            request,
            settings.RESOLVER_REGISTRY_MAX_REQUEST_BYTES,
        )
    except RequestBodyTooLarge:
        metrics.inc(
            "prophet_resolver_registry_request_rejected_total",
            labels={"reason": "payload_too_large"},
        )
        metrics.inc(
            "prophet_resolver_registry_publish_total",
            labels={"result": "payload_too_large"},
        )
        raise HTTPException(status_code=413, detail="Payload too large")

    try:
        body = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
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
