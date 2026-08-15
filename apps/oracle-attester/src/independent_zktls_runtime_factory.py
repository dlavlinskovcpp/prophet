"""Startup wiring for the existing independent zkTLS verifier implementation."""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

from .resolver_v2_independent_verifier import IndependentProofChecker, IndependentZkTlsVerifier
from .resolver_v2_pipeline import PipelineRejected
from .runtime_adapter_factory import RuntimeAdapterRegistry

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


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
        from .resolver_v2_independent_verifier import IndependentProofClaims
        return IndependentProofClaims(encoded_proof == b"proof", "1", "api.example", "1e" * 32, "1f" * 32, sha256(response_bytes).hexdigest())
