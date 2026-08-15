"""Pure, single-implementation Resolver V2 verification runtime."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .resolver_v2_pipeline import PipelineRejected, verification_result_from_report

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


@dataclass(frozen=True)
class ResolverVerifierRuntime:
    """Trusted startup wiring for exactly one verifier implementation."""

    runtime_config: Any
    adapter_factory: Any
    verifier_descriptor: Mapping[str, Any]

    def __post_init__(self) -> None:
        try:
            descriptor = resolver_v2._validate_adapter(self.verifier_descriptor)
        except resolver_v2.ResolverV2Error as exc:
            raise PipelineRejected("runtime_verifier_identity_invalid") from exc
        configured = getattr(self.runtime_config, "verifier", None)
        if configured is None or (descriptor["adapter_id"], descriptor["adapter_version"]) != (configured.implementation_id, configured.version):
            raise PipelineRejected("runtime_verifier_identity_mismatch")
        object.__setattr__(self, "verifier_descriptor", MappingProxyType(dict(descriptor)))

    def verify(self, *, resolver_definition: Mapping[str, Any], evidence: Mapping[str, Any], trust_model: Mapping[str, Any]) -> dict[str, Any]:
        """Verify one canonical evidence envelope with the configured implementation."""
        try:
            resolver_v2.validate_resolver_definition(resolver_definition)
            resolver_v2.validate_evidence_envelope(evidence)
            resolver_v2._validate_trust_model(trust_model)
            definition_hash = resolver_v2.resolver_definition_hash(resolver_definition).hex()
            if evidence["definition_hash"] != definition_hash:
                raise PipelineRejected("runtime_resolver_evidence_mismatch")
            if resolver_definition["trust_model"] != trust_model:
                raise PipelineRejected("runtime_trust_model_mismatch")
            adapter = self.adapter_factory.create(resolver_definition)
            report = adapter.verify(resolver_definition, evidence, trust_model)
            if report.verifier != dict(self.verifier_descriptor):
                raise PipelineRejected("runtime_verifier_identity_mismatch")
            return verification_result_from_report(definition_hash=definition_hash, evidence=evidence, report=report)
        except (PipelineRejected, KeyError, ValueError, resolver_v2.ResolverV2Error) as exc:
            raise PipelineRejected("runtime_verification_rejected") from exc
