"""Credential-free production settlement orchestration.

The coordinator owns only public role bindings, signed grant paths, and the
durable journal.  Each signer call is preceded by a journal reservation; a
crash after a remote call therefore becomes UNCERTAIN instead of an automatic
re-sign.
"""
from __future__ import annotations

import os
from typing import Any, Mapping

from .agreed_settlement_signer import CoordinatorSigningBindingError, canonical_message_for_agreed_job
from .external_threshold_validator import ExternalThresholdBundleValidator
from .production_external_signers import ExternalFixedRoleSignerPair, ExternalSignerBoundaryError
from .resolution_coordinator_store import AGREED, CoordinatorRejected, ResolutionCoordinatorStore
from .runtime_config import ResolverRuntimeConfig
from .signing_journal import SigningJournal, SigningJournalError, settlement_signing_scope
from .vault_transit_signer_identity import VaultTransitSignature
from .signer_admission_grant import AUTHORIZATION_SCHEMA, AUTHORIZATION_VERSION, StrictSignerAuthorizationRequestV1, decode_strict_json

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


class ProductionSettlementExecutorError(RuntimeError):
    pass


class ProductionSettlementExecutor:
    """Complete the external A+B -> durable transaction submission path."""

    def __init__(self, *, state: ResolutionCoordinatorStore, runtime_config: ResolverRuntimeConfig, signer_pair: ExternalFixedRoleSignerPair, journal: SigningJournal, bundle_validator: ExternalThresholdBundleValidator, simulation_service: Any, submission_service: Any) -> None:
        self.state = state
        self.runtime_config = runtime_config
        self.signer_pair = signer_pair
        self.journal = journal
        self.bundle_validator = bundle_validator
        self.simulation_service = simulation_service
        self.submission_service = submission_service

    def close(self) -> None:
        self.journal.close()
        for resource in (self.simulation_service, self.submission_service):
            close = getattr(resource, "close", None)
            if close is not None:
                close()

    def execute(self, job: Any, *, attestation_a: Mapping[str, Any] | None, attestation_b: Mapping[str, Any] | None) -> Any:
        if getattr(job, "state", None) != AGREED:
            raise ProductionSettlementExecutorError("settlement_requires_agreed_job")
        if not isinstance(attestation_a, Mapping) or not isinstance(attestation_b, Mapping):
            raise ProductionSettlementExecutorError("verifier_attestations_required")
        request_bytes = self._authorization_request(job, attestation_a, attestation_b)
        try:
            message = canonical_message_for_agreed_job(self.state, job)
        except CoordinatorSigningBindingError as exc:
            raise ProductionSettlementExecutorError("canonical_settlement_binding_invalid") from exc
        intent = self.bundle_validator.prepare_2_of_2(message, coordinator_job_id=job.job_id)
        scope = settlement_signing_scope(message)
        grants = self.runtime_config.external_signers
        if grants is None:
            raise ProductionSettlementExecutorError("external_signer_configuration_missing")
        grant_paths = {"A": os.getenv(grants.signer_a.grant_path_env, ""), "B": os.getenv(grants.signer_b.grant_path_env, "")}
        if not grant_paths["A"] or not grant_paths["B"]:
            raise ProductionSettlementExecutorError("external_signer_grant_path_unresolved")
        for role in ("A", "B"):
            try:
                persisted = self.journal.begin_signer(scope, role)
                if persisted is not None:
                    continue
                signed = self.signer_pair.sign_one(role, request_bytes, message, grant_path=grant_paths[role])
                self.journal.record_signature(
                    scope,
                    role,
                    VaultTransitSignature(signed.signer_id, signed.key_version, signed.public_key, signed.signature, signed.canonical_message_digest),
                )
            except (SigningJournalError, ExternalSignerBoundaryError) as exc:
                raise ProductionSettlementExecutorError(f"external_signer_{role.lower()}_failed") from exc
        try:
            self.journal.validate_completed_intent(scope)
            return self.submission_service.submit_settlement(job.job_id)
        except Exception as exc:
            if isinstance(exc, ProductionSettlementExecutorError):
                raise
            raise ProductionSettlementExecutorError("durable_settlement_submission_failed") from exc

    def _authorization_request(self, job: Any, attestation_a: Mapping[str, Any], attestation_b: Mapping[str, Any]) -> bytes:
        try:
            context = self.state.get_settlement_context(job.job_id)
            if context.program_id != self.runtime_config.solana.prophet_program_id:
                raise ValueError
            request = {
                "schema": AUTHORIZATION_SCHEMA,
                "version": AUTHORIZATION_VERSION,
                "cluster_genesis_hash": self.runtime_config.solana.genesis_hash,
                "program_id": self.runtime_config.solana.prophet_program_id,
                "market": job.market,
                "verifier_a_attestation": dict(attestation_a),
                "verifier_b_attestation": dict(attestation_b),
            }
            parsed = StrictSignerAuthorizationRequestV1.from_mapping(request)
            context_values = {
                "cluster_genesis_hash": self.runtime_config.solana.genesis_hash,
                "program_id": self.runtime_config.solana.prophet_program_id,
                "market": job.market,
                "resolver_definition_hash": job.resolver_definition_hash,
                "evidence_hash": job.evidence_hash,
                "outcome": job.outcome,
                "proof_hash": context.proof_hash,
                "public_inputs_hash": context.public_inputs_hash,
            }
            for slot, attestation in (("A", attestation_a), ("B", attestation_b)):
                payload = attestation.get("payload")
                expected_verifier = job.verifier_a if slot == "A" else job.verifier_b
                if not isinstance(payload, Mapping) or any(payload.get(key) != value for key, value in context_values.items()):
                    raise ValueError
                if (payload.get("verifier_id"), payload.get("verifier_version"), payload.get("verifier_implementation_digest")) != (expected_verifier["adapter_id"], expected_verifier["adapter_version"], expected_verifier["implementation_digest"]):
                    raise ValueError
            encoded = resolver_v2.canonical_json_bytes(parsed.as_mapping())
            if decode_strict_json(encoded) != parsed.as_mapping():
                raise ValueError
            return encoded
        except (CoordinatorRejected, ValueError, TypeError, resolver_v2.ResolverV2Error) as exc:
            raise ProductionSettlementExecutorError("strict_signer_authorization_request_invalid") from exc
