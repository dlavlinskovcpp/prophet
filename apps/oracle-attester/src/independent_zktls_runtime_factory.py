"""Startup wiring for the existing independent zkTLS verifier implementation."""
from __future__ import annotations

import base64
import os
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

import httpx

from .resolver_v2_independent_verifier import (
    IndependentProofChecker,
    IndependentProofClaims,
    IndependentZkTlsVerifier,
)
from .resolver_v2_pipeline import PipelineRejected
from .runtime_adapter_factory import RuntimeAdapterRegistry

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


INDEPENDENT_BOUND_HTTP_BACKEND = "independent-bound-http"


class IndependentZkTlsRuntimeFactory:
    """Construct verifier B directly; it never invokes the primary adapter."""

    def __init__(self, *, runtime_config: Any, verifier_descriptor: Mapping[str, Any], checker: IndependentProofChecker, registry: Optional[RuntimeAdapterRegistry] = None, clock_ms: Optional[Callable[[], int]] = None):
        try:
            descriptor = resolver_v2._validate_adapter(verifier_descriptor)
        except resolver_v2.ResolverV2Error as exc:
            raise PipelineRejected("independent_runtime_verifier_identity_invalid") from exc
        configured = getattr(runtime_config, "verifier", None)
        if configured is None or (descriptor["adapter_id"], descriptor["adapter_version"]) != (configured.implementation_id, configured.version):
            raise PipelineRejected("independent_runtime_verifier_identity_mismatch")
        if "zktls" not in getattr(runtime_config, "allowed_adapters", ()) or getattr(runtime_config, "zktls", None) is None:
            raise PipelineRejected("independent_runtime_zktls_not_enabled")
        self.runtime_config = runtime_config
        self.verifier_descriptor = MappingProxyType(dict(descriptor))
        self.checker, self.registry, self.clock_ms = checker, registry or RuntimeAdapterRegistry(), clock_ms

    def create(self, resolver_definition: Mapping[str, Any]) -> IndependentZkTlsVerifier:
        descriptor = self.registry.resolve(resolver_definition)
        if descriptor.resolver_type != "zktls":
            raise PipelineRejected("independent_runtime_adapter_unsupported")
        return IndependentZkTlsVerifier(dict(self.verifier_descriptor), self.checker, clock_ms=self.clock_ms)


class DeterministicTestIndependentProofChecker:
    """Test-only independent checker for the existing deterministic fixture."""
    def validate(self, encoded_proof: bytes, response_bytes: bytes):
        from hashlib import sha256
        return IndependentProofClaims(encoded_proof == b"proof", "1", "api.example", "1e" * 32, "1f" * 32, sha256(response_bytes).hexdigest())


class BoundHttpIndependentProofChecker:
    """Verifier-B-only production checker with independent HTTP/parsing code."""

    def __init__(self, *, url: str, token: str, timeout_seconds: float) -> None:
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise PipelineRejected("independent_zktls_url_invalid") from exc
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise PipelineRejected("independent_zktls_requires_https")
        if not token:
            raise PipelineRejected("independent_zktls_token_missing")
        self._url, self._token, self._timeout = url.rstrip("/"), token, timeout_seconds

    @classmethod
    def from_environment(cls, *, timeout_seconds: float) -> "BoundHttpIndependentProofChecker":
        url = os.getenv("PROPHET_ZKTLS_VERIFY_URL", "").strip()
        token = os.getenv("PROPHET_ZKTLS_VERIFY_TOKEN", "")
        if not url or not token:
            raise PipelineRejected("independent_zktls_dependency_unresolved")
        return cls(url=url, token=token, timeout_seconds=timeout_seconds)

    def validate(self, encoded_proof: bytes, response_bytes: bytes) -> IndependentProofClaims:
        request = {
            "schema": "prophet.independent-zktls-proof-verification.v1",
            "proof_b64": base64.b64encode(encoded_proof).decode("ascii"),
            "response_b64": base64.b64encode(response_bytes).decode("ascii"),
        }
        try:
            response = httpx.post(
                self._url,
                json=request,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self._timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            raise PipelineRejected("independent_zktls_verifier_unavailable") from exc
        keys = {
            "valid", "proof_version", "source_domain", "request_definition_hash",
            "cluster_genesis_hash", "response_hash",
        }
        if not isinstance(payload, dict) or set(payload) != keys or not isinstance(payload["valid"], bool):
            raise PipelineRejected("independent_zktls_response_invalid")
        return IndependentProofClaims(
            payload["valid"],
            str(payload["proof_version"]),
            str(payload["source_domain"]),
            str(payload["request_definition_hash"]),
            str(payload["cluster_genesis_hash"]),
            str(payload["response_hash"]),
        )
