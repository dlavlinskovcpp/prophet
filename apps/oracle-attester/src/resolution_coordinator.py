"""Sequential, resumable orchestration over existing verifier clients and state."""
from __future__ import annotations

import uuid
from typing import Any, Mapping, Optional

from .resolution_coordinator_store import (
    CoordinatorRejected,
    ResolutionCoordinatorStore,
    ResolutionJob,
    SettlementMessageContext,
    SettlementRuntimeBinding,
)
from .verifier_service_client import VerifierClientError, VerifierServiceClient


class ResolutionCoordinatorError(RuntimeError):
    """Safe orchestration failure; canonical verifier results are never fabricated."""


class ResolutionCoordinatorConfigurationError(ResolutionCoordinatorError): pass
class ResolutionCoordinatorVerifierFailure(ResolutionCoordinatorError): pass
class ResolutionCoordinatorPersistenceFailure(ResolutionCoordinatorError): pass


class ResolutionCoordinator:
    """One-shot A→B orchestration with durable resume and no retry/fallback policy."""

    def __init__(
        self,
        *,
        state: ResolutionCoordinatorStore,
        verifier_client_a: VerifierServiceClient,
        verifier_client_b: VerifierServiceClient,
    ) -> None:
        self.state = state
        self.verifier_client_a = verifier_client_a
        self.verifier_client_b = verifier_client_b
        self._validate_wiring()

    def resolve(
        self,
        *,
        market: str,
        resolver_definition: Mapping[str, Any],
        evidence: Mapping[str, Any],
        trust_model: Mapping[str, Any],
        correlation_id: Optional[str] = None,
        settlement_context: SettlementMessageContext | None = None,
        settlement_runtime: SettlementRuntimeBinding | None = None,
    ) -> ResolutionJob:
        """Persist only missing verifier results; terminal jobs produce no network calls."""
        try:
            job = self.state.register_job(
                market=market,
                resolver_definition=resolver_definition,
                evidence=evidence,
            )
        except CoordinatorRejected as exc:
            raise ResolutionCoordinatorPersistenceFailure("resolution_job_registration_failed") from exc
        if settlement_context is not None:
            try:
                self.state.bind_settlement_context(job.job_id, settlement_context)
            except CoordinatorRejected as exc:
                raise ResolutionCoordinatorPersistenceFailure("settlement_context_binding_failed") from exc
        if settlement_runtime is not None:
            try:
                self.state.bind_settlement_runtime(job.job_id, settlement_runtime)
            except CoordinatorRejected as exc:
                raise ResolutionCoordinatorPersistenceFailure("settlement_runtime_binding_failed") from exc
        if job.state in {"AGREED", "CONFLICT"}:
            return job

        request_id = self._correlation_id(correlation_id)
        if job.verifier_a_result is None:
            result = self._call(
                slot="A",
                client=self.verifier_client_a,
                resolver_definition=resolver_definition,
                evidence=evidence,
                trust_model=trust_model,
                request_id=request_id,
            )
            job = self._record(job.job_id, "A", result)
        if job.state in {"AGREED", "CONFLICT"}:
            return job
        if job.verifier_b_result is None:
            result = self._call(
                slot="B",
                client=self.verifier_client_b,
                resolver_definition=resolver_definition,
                evidence=evidence,
                trust_model=trust_model,
                request_id=request_id,
            )
            job = self._record(job.job_id, "B", result)
        return job

    def _validate_wiring(self) -> None:
        for slot, client, binding in (
            ("A", self.verifier_client_a, self.state.verifier_a),
            ("B", self.verifier_client_b, self.state.verifier_b),
        ):
            if getattr(client, "slot", None) != slot:
                raise ResolutionCoordinatorConfigurationError("verifier_client_slot_mismatch")
            config = getattr(client, "config", None)
            expected = (
                getattr(config, "expected_verifier_id", None),
                getattr(config, "expected_verifier_version", None),
                getattr(config, "expected_verifier_implementation_digest", None),
            )
            actual = (
                binding.descriptor["adapter_id"],
                binding.descriptor["adapter_version"],
                binding.descriptor["implementation_digest"],
            )
            if expected != actual:
                raise ResolutionCoordinatorConfigurationError("verifier_client_identity_mismatch")

    @staticmethod
    def _correlation_id(value: Optional[str]) -> str:
        if value and len(value) <= 64 and all(char.isascii() and (char.isalnum() or char in "._-") for char in value):
            return value
        return uuid.uuid4().hex

    @staticmethod
    def _call(*, slot: str, client: VerifierServiceClient, **request: Any) -> Mapping[str, Any]:
        try:
            return client.verify(**request)
        except VerifierClientError as exc:
            raise ResolutionCoordinatorVerifierFailure(f"verifier_{slot.lower()}_service_failure") from exc

    def _record(self, job_id: str, slot: str, result: Mapping[str, Any]) -> ResolutionJob:
        try:
            return self.state.record_result(job_id=job_id, slot=slot, result=result)
        except CoordinatorRejected as exc:
            raise ResolutionCoordinatorPersistenceFailure(f"verifier_{slot.lower()}_result_persistence_failed") from exc
