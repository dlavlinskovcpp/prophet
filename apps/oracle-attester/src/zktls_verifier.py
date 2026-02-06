import logging
import httpx
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any
from .config import settings
from .resolver import ResolverDefinition
from .zktls_providers.reclaim_http import build_verify_payload, parse_verify_response

logger = logging.getLogger(__name__)

@dataclass
class ZkTlsVerifyResult:
    ok: bool
    reason: str = ""
    provider: str = ""
    meta: Optional[Dict[str, Any]] = None

class ZkTlsVerifier(ABC):
    @abstractmethod
    def verify(self, *, resolver: ResolverDefinition, proof_bytes: bytes, public_inputs_bytes: bytes) -> ZkTlsVerifyResult:
        pass

class ReclaimHttpVerifier(ZkTlsVerifier):
    def verify(self, *, resolver: ResolverDefinition, proof_bytes: bytes, public_inputs_bytes: bytes) -> ZkTlsVerifyResult:
        if not proof_bytes:
            return ZkTlsVerifyResult(ok=False, reason="missing_proof", provider="reclaim_http")
        if not public_inputs_bytes:
            return ZkTlsVerifyResult(ok=False, reason="missing_public_inputs", provider="reclaim_http")

        url = settings.RECLAIM_VERIFY_URL
        if not url:
            return ZkTlsVerifyResult(ok=False, reason="RECLAIM_VERIFY_URL not configured", provider="reclaim_http")

        # Use contract module to build payload
        payload = build_verify_payload(resolver, proof_bytes, public_inputs_bytes)

        headers = {}
        if settings.RECLAIM_API_KEY:
            headers["Authorization"] = f"Bearer {settings.RECLAIM_API_KEY}"

        try:
            with httpx.Client(timeout=settings.ZKTLS_HTTP_TIMEOUT_S) as client:
                resp = client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                
                # Use contract module to parse response
                is_valid, reason, meta = parse_verify_response(resp.json())
                
                return ZkTlsVerifyResult(
                    ok=is_valid, 
                    reason=reason, 
                    provider="reclaim_http",
                    meta=meta
                )
        except Exception as e:
            logger.error(f"Reclaim verification HTTP error: {e}")
            return ZkTlsVerifyResult(ok=False, reason=f"http_error: {str(e)}", provider="reclaim_http")

def make_verifier() -> ZkTlsVerifier:
    mode = settings.ZKTLS_MODE.lower()
    if mode == "reclaim_http":
        return ReclaimHttpVerifier()
    raise ValueError(
        f"Unsupported ZKTLS_MODE '{settings.ZKTLS_MODE}'. Only reclaim_http is allowed."
    )
