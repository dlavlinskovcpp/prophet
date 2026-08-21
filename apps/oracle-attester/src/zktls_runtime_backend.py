"""Allowlisted zkTLS proof-verifier backends for verifier runtimes only."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any
from urllib.parse import urlsplit

import httpx

from .bounded_http_response import (
    BoundedHttpResponseHeaderError,
    BoundedHttpResponseTooLarge,
    read_bounded_response_bytes,
)
from .resolver_v2_adapters import ZkTlsClaims, ZkTlsExpectedBinding, ZkTlsProofVerifier
from .resolver_v2_pipeline import PipelineRejected


DETERMINISTIC_TEST_BACKEND = "deterministic-test"
BOUND_HTTP_BACKEND = "bound-http"
_HTTP_URL_ENV = "PROPHET_ZKTLS_VERIFY_URL"
_HTTP_TOKEN_ENV = "PROPHET_ZKTLS_VERIFY_TOKEN"


class DeterministicTestZkTlsProofVerifier:
    """Test-only backend for the explicit `b"proof"` fixture contract."""

    backend_id = DETERMINISTIC_TEST_BACKEND

    def verify(self, *, proof_bytes: bytes, response_bytes: bytes, expected_binding: ZkTlsExpectedBinding) -> ZkTlsClaims:
        valid = proof_bytes == b"proof" and bool(response_bytes)
        return ZkTlsClaims(
            valid=valid,
            proof_version=expected_binding.proof_version,
            source_domain=expected_binding.source_domain,
            request_definition_hash=expected_binding.request_definition_hash,
            cluster_genesis_hash=expected_binding.cluster_genesis_hash,
            response_hash=hashlib.sha256(response_bytes).hexdigest(),
            reason="deterministic_test_proof_invalid" if not valid else "",
        )


def _production_endpoint() -> tuple[str, str]:
    url = os.getenv(_HTTP_URL_ENV, "").strip()
    token = os.getenv(_HTTP_TOKEN_ENV, "")
    if not url or not token:
        raise PipelineRejected("runtime_zktls_http_dependency_unresolved")
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise PipelineRejected("runtime_zktls_http_url_invalid") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise PipelineRejected("runtime_zktls_http_requires_https")
    return url.rstrip("/"), token


class BoundHttpZkTlsProofVerifier:
    """Primary production checker bound to one external proof-verifier domain."""

    backend_id = BOUND_HTTP_BACKEND

    def __init__(self, *, url: str, token: str, timeout_seconds: float, max_response_bytes: int) -> None:
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes <= 0:
            raise PipelineRejected("runtime_zktls_http_response_limit_invalid")
        self._url, self._token, self._timeout = url, token, timeout_seconds
        self._max_response_bytes = max_response_bytes

    def verify(self, *, proof_bytes: bytes, response_bytes: bytes, expected_binding: ZkTlsExpectedBinding) -> ZkTlsClaims:
        request = {
            "schema": "prophet.zktls-proof-verification.v1",
            "proof_b64": base64.b64encode(proof_bytes).decode("ascii"),
            "response_b64": base64.b64encode(response_bytes).decode("ascii"),
            "expected_binding": {
                "proof_version": expected_binding.proof_version,
                "source_domain": expected_binding.source_domain,
                "request_definition_hash": expected_binding.request_definition_hash,
                "cluster_genesis_hash": expected_binding.cluster_genesis_hash,
            },
        }
        try:
            with httpx.Client(timeout=self._timeout) as client:
                with client.stream(
                    "POST",
                    self._url,
                    json=request,
                    headers={"Authorization": f"Bearer {self._token}"},
                ) as response:
                    response.raise_for_status()
                    raw = read_bounded_response_bytes(
                        response,
                        max_bytes=self._max_response_bytes,
                    )
        except BoundedHttpResponseTooLarge as exc:
            raise PipelineRejected("runtime_zktls_http_response_too_large") from exc
        except BoundedHttpResponseHeaderError as exc:
            raise PipelineRejected("runtime_zktls_http_response_invalid") from exc
        except Exception as exc:
            raise PipelineRejected("runtime_zktls_http_verifier_unavailable") from exc

        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PipelineRejected("runtime_zktls_http_response_invalid") from exc

        keys = {
            "valid", "proof_version", "source_domain", "request_definition_hash",
            "cluster_genesis_hash", "response_hash", "reason",
        }
        if not isinstance(payload, dict) or set(payload) != keys or not isinstance(payload["valid"], bool):
            raise PipelineRejected("runtime_zktls_http_response_invalid")
        return ZkTlsClaims(
            valid=payload["valid"],
            proof_version=str(payload["proof_version"]),
            source_domain=str(payload["source_domain"]),
            request_definition_hash=str(payload["request_definition_hash"]),
            cluster_genesis_hash=str(payload["cluster_genesis_hash"]),
            response_hash=str(payload["response_hash"]),
            reason=str(payload["reason"]),
        )


def make_zktls_proof_verifier(runtime_config: Any) -> ZkTlsProofVerifier:
    """Resolve only explicit allowlisted backends; no fallback exists."""
    configured = getattr(runtime_config, "zktls", None)
    if configured is None or "zktls" not in getattr(runtime_config, "allowed_adapters", ()):
        raise PipelineRejected("runtime_zktls_not_enabled")
    if configured.verifier_backend == DETERMINISTIC_TEST_BACKEND:
        if getattr(runtime_config, "mode", None) != "test":
            raise PipelineRejected("runtime_zktls_test_backend_not_allowed")
        return DeterministicTestZkTlsProofVerifier()
    if configured.verifier_backend == BOUND_HTTP_BACKEND:
        if getattr(runtime_config, "mode", None) != "production":
            raise PipelineRejected("runtime_zktls_http_backend_requires_production")
        url, token = _production_endpoint()
        return BoundHttpZkTlsProofVerifier(
            url=url,
            token=token,
            timeout_seconds=float(runtime_config.limits.request_timeout_seconds),
            max_response_bytes=int(runtime_config.limits.request_max_bytes),
        )
    raise PipelineRejected("runtime_zktls_backend_unavailable")
