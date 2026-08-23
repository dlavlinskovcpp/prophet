"""Pure, single-implementation Resolver V2 verification runtime."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

from .resolver_v2_pipeline import PipelineRejected, verification_result_from_report
from .runtime_clock import wall_clock_ms

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
    attestation_signer: Any = None
    clock_ms: Optional[Callable[[], int]] = None

    def __post_init__(self) -> None:
        try:
            descriptor = resolver_v2._validate_adapter(self.verifier_descriptor)
        except resolver_v2.ResolverV2Error as exc:
            raise PipelineRejected("runtime_verifier_identity_invalid") from exc
        configured = getattr(self.runtime_config, "verifier", None)
        if configured is None or (descriptor["adapter_id"], descriptor["adapter_version"]) != (configured.implementation_id, configured.version):
            raise PipelineRejected("runtime_verifier_identity_mismatch")
        object.__setattr__(self, "verifier_descriptor", MappingProxyType(dict(descriptor)))
        if self.clock_ms is not None and not callable(self.clock_ms):
            raise PipelineRejected("runtime_clock_invalid")
        if self.attestation_signer is not None and getattr(self.runtime_config, "mode", None) == "production" and self.clock_ms is None:
            raise PipelineRejected("runtime_attestation_clock_missing")

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

    def verify_attested(
        self,
        *,
        resolver_definition: Mapping[str, Any],
        evidence: Mapping[str, Any],
        trust_model: Mapping[str, Any],
        attestation_context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return an authenticated result without changing Resolver V2 result bytes."""
        if self.attestation_signer is None:
            raise PipelineRejected("runtime_attestation_signer_missing")
        try:
            from .verifier_attestation import payload_from_verification_result
            required = {"cluster_genesis_hash", "program_id", "market", "proof_hash", "public_inputs_hash"}
            if not isinstance(attestation_context, Mapping) or set(attestation_context) != required:
                raise ValueError
            result = self.verify(
                resolver_definition=resolver_definition, evidence=evidence, trust_model=trust_model
            )
            now_ms = (self.clock_ms or wall_clock_ms)()
            payload = payload_from_verification_result(result, **dict(attestation_context), now_ms=now_ms)
            return {"verification_result": result, "attestation": self.attestation_signer.sign(payload, now_ms=now_ms).as_transport()}
        except (ValueError, KeyError) as exc:
            raise PipelineRejected("runtime_attestation_context_invalid") from exc
