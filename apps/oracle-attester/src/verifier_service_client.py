"""Strict outbound client for one identity-bound Resolver V2 verifier service."""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Mapping, Optional

import httpx

from .runtime_config import CoordinatorVerifierServiceConfig, ResolverRuntimeConfig

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


logger = logging.getLogger("prophet.verifier-client")


class VerifierClientError(RuntimeError):
    """Safe, typed verifier-service client failure."""


class VerifierClientConfigurationError(VerifierClientError): pass
class VerifierClientAuthenticationError(VerifierClientError): pass
class VerifierClientTimeout(VerifierClientError): pass
class VerifierClientTransportError(VerifierClientError): pass
class VerifierClientRemoteServiceError(VerifierClientError): pass
class VerifierClientMalformedResponse(VerifierClientError): pass
class VerifierClientIdentityMismatch(VerifierClientError): pass
class VerifierClientBindingMismatch(VerifierClientError): pass
class VerifierClientRequestError(VerifierClientError): pass


class VerifierServiceClient:
    """A one-endpoint client with no retry, local verifier, or A/B fallback path."""

    def __init__(
        self,
        *,
        slot: str,
        config: CoordinatorVerifierServiceConfig,
        bearer_token: str,
        response_max_bytes: int,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        if slot not in ("A", "B"):
            raise VerifierClientConfigurationError("unsupported_verifier_slot")
        if not bearer_token:
            raise VerifierClientAuthenticationError("missing_verifier_bearer_token")
        if response_max_bytes <= 0:
            raise VerifierClientConfigurationError("invalid_response_size_limit")
        self.slot = slot
        self.config = config
        self._token = bearer_token
        self._response_max_bytes = response_max_bytes
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(follow_redirects=False, trust_env=False)

    @classmethod
    def from_runtime(
        cls,
        runtime_config: ResolverRuntimeConfig,
        *,
        slot: str,
        http_client: Optional[httpx.Client] = None,
    ) -> "VerifierServiceClient":
        if runtime_config.coordinator is None:
            raise VerifierClientConfigurationError("coordinator_verifier_configuration_missing")
        if slot == "A":
            config = runtime_config.coordinator.verifier_a
        elif slot == "B":
            config = runtime_config.coordinator.verifier_b
        else:
            raise VerifierClientConfigurationError("unsupported_verifier_slot")
        token = os.getenv(config.auth_token_env, "")
        if not token:
            raise VerifierClientAuthenticationError("missing_verifier_bearer_token")
        return cls(
            slot=slot,
            config=config,
            bearer_token=token,
            response_max_bytes=runtime_config.limits.request_max_bytes,
            http_client=http_client,
        )

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def verify(
        self,
        *,
        resolver_definition: Mapping[str, Any],
        evidence: Mapping[str, Any],
        trust_model: Mapping[str, Any],
        request_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Send one unchanged canonical runtime request and validate its result binding."""
        try:
            definition = resolver_v2.validate_resolver_definition(resolver_definition)
            canonical_evidence = resolver_v2.validate_evidence_envelope(evidence)
            canonical_trust = resolver_v2._validate_trust_model(trust_model)
            definition_hash = resolver_v2.resolver_definition_hash(definition).hex()
            evidence_hash = resolver_v2.evidence_hash(canonical_evidence).hex()
            if canonical_evidence["definition_hash"] != definition_hash or definition["trust_model"] != canonical_trust:
                raise VerifierClientRequestError("canonical_request_binding_mismatch")
            body = resolver_v2.canonical_json_bytes({
                "resolver_definition": definition,
                "evidence": canonical_evidence,
                "trust_model": canonical_trust,
            })
        except VerifierClientError:
            raise
        except (ValueError, resolver_v2.ResolverV2Error) as exc:
            raise VerifierClientRequestError("invalid_canonical_verification_request") from exc

        correlation_id = request_id if request_id and len(request_id) <= 64 and request_id.isascii() else uuid.uuid4().hex
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "X-Request-ID": correlation_id,
        }
        started = time.perf_counter()
        status_category = "transport"
        try:
            with self._http.stream(
                "POST",
                f"{self.config.base_url.rstrip('/')}/v1/verify",
                content=body,
                headers=headers,
                timeout=self.config.request_timeout_seconds,
                follow_redirects=False,
            ) as response:
                status_category = str(response.status_code)
                declared = response.headers.get("content-length")
                if declared is not None and (not declared.isdigit() or int(declared) > self._response_max_bytes):
                    raise VerifierClientMalformedResponse("remote_response_too_large")
                raw = self._bounded_response(response)
                self._check_status(response.status_code)
        except VerifierClientError:
            raise
        except httpx.TimeoutException as exc:
            raise VerifierClientTimeout("verifier_service_timeout") from exc
        except httpx.HTTPError as exc:
            raise VerifierClientTransportError("verifier_service_transport_error") from exc
        finally:
            logger.info(json.dumps({
                "event": "coordinator_verifier_call",
                "slot": self.slot,
                "expected_verifier_id": self.config.expected_verifier_id,
                "request_id": correlation_id,
                "status_category": status_category,
                "latency_ms": int((time.perf_counter() - started) * 1000),
            }, sort_keys=True))

        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("response is not an object")
            result = resolver_v2.validate_verification_result(parsed)
        except (ValueError, json.JSONDecodeError, resolver_v2.ResolverV2Error) as exc:
            raise VerifierClientMalformedResponse("invalid_verification_result_response") from exc
        verifier = result["verifier"]
        if (
            verifier["adapter_id"] != self.config.expected_verifier_id
            or verifier["adapter_version"] != self.config.expected_verifier_version
            or verifier["implementation_digest"] != self.config.expected_verifier_implementation_digest
        ):
            raise VerifierClientIdentityMismatch("unexpected_remote_verifier_identity")
        if result["definition_hash"] != definition_hash or result["evidence_hash"] != evidence_hash:
            raise VerifierClientBindingMismatch("verification_result_request_binding_mismatch")
        return result

    def _bounded_response(self, response: httpx.Response) -> bytes:
        parts: list[bytes] = []
        size = 0
        for part in response.iter_bytes():
            size += len(part)
            if size > self._response_max_bytes:
                raise VerifierClientMalformedResponse("remote_response_too_large")
            parts.append(part)
        return b"".join(parts)

    @staticmethod
    def _check_status(status: int) -> None:
        if status == 200:
            return
        if status in (401, 403):
            raise VerifierClientAuthenticationError("verifier_service_authorization_failed")
        if 300 <= status < 400:
            raise VerifierClientRemoteServiceError("verifier_service_redirect_rejected")
        if status in (400, 413, 422, 429) or status >= 500:
            raise VerifierClientRemoteServiceError("verifier_service_rejected_request")
        raise VerifierClientRemoteServiceError("unexpected_verifier_service_status")
