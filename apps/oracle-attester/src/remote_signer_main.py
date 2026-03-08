import base64
import hmac
import logging
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict, Optional, Set, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from .config import settings

logger = logging.getLogger("remote-signer")


class SignRequest(BaseModel):
    public_key: str = Field(..., description="Notary pubkey (base58)")
    message_b64: str = Field(..., description="Message to sign, base64 encoded")
    context: Dict[str, str] = Field(default_factory=dict, description="Optional audit context")


class SignResponse(BaseModel):
    signature_b64: str
    public_key: str


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


def _load_keypair(path_or_str: str) -> Optional[Keypair]:
    return settings._load_keypair(path_or_str)


def _load_signers() -> Dict[str, Keypair]:
    raw = (settings.NOTARY_KEYPAIR_PATHS or "").strip()
    if raw:
        sources = [x.strip() for x in raw.split(",") if x.strip()]
    else:
        # Local/dev fallback only. In production, service should still point to explicit signer keys.
        sources = [settings.ORACLE_KEYPAIR_PATH]

    out: Dict[str, Keypair] = {}
    for src in sources:
        kp = _load_keypair(src)
        if kp is None:
            logger.warning(f"Skipping invalid keypair source: {src}")
            continue
        out[str(kp.pubkey())] = kp
    return out


def _parse_allowed_pubkeys(raw: str) -> Set[str]:
    raw = (raw or "").strip()
    if not raw:
        return set()
    out: Set[str] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        # Normalize/validate
        out.add(str(Pubkey.from_string(item)))
    return out


def _validate_remote_signer_runtime() -> None:
    if settings.REMOTE_SIGNER_REQUIRE_AUTH and not settings.REMOTE_SIGNER_API_KEY:
        raise ValueError("REMOTE_SIGNER_API_KEY is required when REMOTE_SIGNER_REQUIRE_AUTH=1.")
    if settings.REMOTE_SIGNER_MAX_MESSAGE_BYTES <= 0:
        raise ValueError("REMOTE_SIGNER_MAX_MESSAGE_BYTES must be > 0.")


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


_validate_remote_signer_runtime()
signer_map = _load_signers()
allowed_pubkeys = _parse_allowed_pubkeys(settings.REMOTE_SIGNER_ALLOWED_PUBKEYS)
metrics = MetricsRegistry()
rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.RATE_LIMIT_MAX_REQUESTS,
    window_s=settings.RATE_LIMIT_WINDOW_S,
)

app = FastAPI(title="Prophet Remote Notary Signer")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method
    status_code = 500

    try:
        if path == "/sign":
            if settings.REMOTE_SIGNER_REQUIRE_AUTH:
                token = _extract_bearer_token(request.headers.get("authorization", ""))
                if not token or not hmac.compare_digest(token, settings.REMOTE_SIGNER_API_KEY):
                    metrics.inc("prophet_remote_signer_auth_failures_total")
                    status_code = 401
                    return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

            if settings.RATE_LIMIT_ENABLED:
                key = _client_ip(request)
                allowed, retry_after = rate_limiter.allow(key)
                if not allowed:
                    metrics.inc("prophet_remote_signer_rate_limited_total")
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
                "prophet_remote_signer_http_requests_total",
                labels={"path": path, "method": method, "status": str(status_code)},
            )


@app.get("/health")
def health():
    return {
        "ok": True,
        "loaded_signers": len(signer_map),
        "allowlist_size": len(allowed_pubkeys),
    }


@app.get("/metrics")
def metrics_endpoint():
    if not settings.METRICS_ENABLED:
        return PlainTextResponse("", media_type="text/plain; version=0.0.4")
    return PlainTextResponse(metrics.render_prometheus(), media_type="text/plain; version=0.0.4")


@app.post("/sign", response_model=SignResponse)
async def sign(req: SignRequest):
    if not signer_map:
        metrics.inc("prophet_remote_signer_sign_total", labels={"result": "no_keys"})
        return JSONResponse(status_code=503, content={"detail": "No signers configured"})

    try:
        pk_str = str(Pubkey.from_string(req.public_key))
    except Exception:
        metrics.inc("prophet_remote_signer_sign_total", labels={"result": "bad_pubkey"})
        return JSONResponse(status_code=400, content={"detail": "Invalid public_key"})

    if allowed_pubkeys and pk_str not in allowed_pubkeys:
        metrics.inc("prophet_remote_signer_sign_total", labels={"result": "not_allowed"})
        return JSONResponse(status_code=403, content={"detail": "Signer not allowed"})

    kp = signer_map.get(pk_str)
    if kp is None:
        metrics.inc("prophet_remote_signer_sign_total", labels={"result": "not_loaded"})
        return JSONResponse(status_code=403, content={"detail": "Signer key unavailable"})

    try:
        msg = base64.b64decode(req.message_b64, validate=True)
    except Exception:
        metrics.inc("prophet_remote_signer_sign_total", labels={"result": "bad_message"})
        return JSONResponse(status_code=400, content={"detail": "Invalid message_b64"})

    if len(msg) > settings.REMOTE_SIGNER_MAX_MESSAGE_BYTES:
        metrics.inc("prophet_remote_signer_sign_total", labels={"result": "message_too_large"})
        return JSONResponse(status_code=413, content={"detail": "Message too large"})

    sig = bytes(kp.sign_message(msg))
    metrics.inc("prophet_remote_signer_sign_total", labels={"result": "success"})
    return SignResponse(
        signature_b64=base64.b64encode(sig).decode("ascii"),
        public_key=pk_str,
    )
