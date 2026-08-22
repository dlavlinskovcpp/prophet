"""Explicit durable AGREED -> strict Vault 2-of-2 signing boundary.

This module is intentionally in-process only. It never mutates coordinator
history, exposes no HTTP endpoint, and constructs/submits no Solana transaction.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Optional

from solders.pubkey import Pubkey

from .resolution_coordinator_store import AGREED, CoordinatorRejected, ResolutionCoordinatorStore, ResolutionJob
from .resolver_v2_multi_verifier import AgreementPolicy, evaluate_agreement
from .resolver_v2_pipeline import PipelineRejected, build_legacy_settlement_message
from .runtime_clock import wall_clock_ms
from .signing_journal import (
    BOTH_SIGNED,
    SigningJournal,
    SigningJournalBindingError,
    SigningJournalConflict,
    SigningJournalError,
    SigningJournalUncertain,
)
from .vault_transit_signer_identity import VaultSignerError
from .vault_transit_threshold_signer import (
    ThresholdResolutionSigner,
    ThresholdResolutionSignerError,
    ThresholdSignatureBundle,
)

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


class AgreedSettlementSigningError(RuntimeError):
    """Base class for safe application-level AGREED signing failures."""


class CoordinatorJobMissing(AgreedSettlementSigningError): pass
class CoordinatorJobNotAgreed(AgreedSettlementSigningError): pass
class CoordinatorSigningBindingError(AgreedSettlementSigningError): pass
class CoordinatorSigningConflict(AgreedSettlementSigningError): pass
class SigningRecoveryRequired(AgreedSettlementSigningError): pass
class SettlementSignerFailure(AgreedSettlementSigningError): pass
class SigningPersistenceError(AgreedSettlementSigningError): pass


@dataclass(frozen=True)
class AgreedSettlementSigningResult:
    coordinator_job_id: str
    signing_intent_id: str
    signing_state: str
    canonical_message_digest: str
    canonical_message: bytes
    signer_a_id: str
    signer_a_public_key: str
    signer_a_key_version: int
    signer_b_id: str
    signer_b_public_key: str
    signer_b_key_version: int
    signature_bundle: ThresholdSignatureBundle


def canonical_message_for_agreed_job(
    coordinator_state: ResolutionCoordinatorStore, job: ResolutionJob
) -> bytes:
    """Derive the existing canonical settlement bytes from durable job state."""
    try:
        context = coordinator_state.get_settlement_context(job.job_id)
    except CoordinatorRejected as exc:
        if str(exc) == "settlement_context_not_found":
            raise CoordinatorSigningBindingError("durable_settlement_context_missing") from exc
        raise CoordinatorSigningBindingError("durable_settlement_context_invalid") from exc
    try:
        market_pubkey = str(Pubkey.from_bytes(bytes.fromhex(job.market)))
        return build_legacy_settlement_message(
            program_id=context.program_id,
            market=market_pubkey,
            notary_config=context.notary_config,
            resolver_hash=job.resolver_definition_hash,
            open_ts=context.open_ts,
            resolve_ts=context.resolve_ts,
            notary_config_version=context.notary_config_version,
            outcome=job.outcome,
            proof_hash=context.proof_hash,
            public_inputs_hash=context.public_inputs_hash,
        )
    except (PipelineRejected, ValueError, OverflowError) as exc:
        raise CoordinatorSigningBindingError("canonical_settlement_construction_rejected") from exc


class AgreedSettlementSigner:
    """Sign exactly the settlement implied by one durable AGREED coordinator job."""

    def __init__(
        self,
        *,
        coordinator_state: ResolutionCoordinatorStore,
        signing_journal: SigningJournal,
        threshold_signer: ThresholdResolutionSigner,
        clock_ms: Optional[Callable[[], int]] = None,
    ) -> None:
        if threshold_signer.journal is not signing_journal:
            raise CoordinatorSigningBindingError("threshold_signer_journal_mismatch")
        self._coordinator_state = coordinator_state
        self._journal = signing_journal
        self._threshold_signer = threshold_signer
        if clock_ms is not None and not callable(clock_ms):
            raise CoordinatorSigningBindingError("settlement_signer_clock_invalid")
        self._clock_ms = clock_ms or wall_clock_ms

    def sign_agreed_job(self, job_id: str) -> AgreedSettlementSigningResult:
        """Create/resume exactly one durable 2/2 intent for an AGREED job.

        `job_id` is a lookup/audit identifier only. All protocol-significant
        settlement data is reloaded from durable coordinator state.
        """
        job = self._load_signable_job(job_id)
        message = self._canonical_message(job)
        digest = hashlib.sha256(message).hexdigest()

        try:
            # Commits the anti-equivocation intent, signer epochs, and durable
            # coordinator->intent provenance before any Vault call can begin.
            intent = self._threshold_signer.prepare_2_of_2(message, coordinator_job_id=job.job_id)
            if intent.canonical_message_digest != digest or intent.canonical_message != message:
                raise CoordinatorSigningBindingError("coordinator_signing_intent_message_mismatch")
            link = self._journal.get_coordinator_link(job.job_id)
            if link.signing_scope_id != intent.signing_scope_id or link.canonical_message_digest != digest:
                raise CoordinatorSigningBindingError("coordinator_signing_link_inconsistent")

            bundle = self._threshold_signer.resume_2_of_2(message)
            self._threshold_signer.validate_bundle(bundle, message)
            completed = self._journal.get(intent.signing_scope_id)
            if completed.state != BOTH_SIGNED or completed.signer_a_result is None or completed.signer_b_result is None:
                raise SigningPersistenceError("completed_signature_bundle_not_durable")
            if completed.canonical_message_digest != bundle.canonical_message_digest:
                raise SigningPersistenceError("completed_signature_bundle_digest_mismatch")
        except SigningJournalConflict as exc:
            raise CoordinatorSigningConflict("anti_equivocation_conflict") from exc
        except SigningJournalBindingError as exc:
            raise CoordinatorSigningBindingError("coordinator_signing_binding_inconsistent") from exc
        except SigningJournalUncertain as exc:
            raise SigningRecoveryRequired("signing_recovery_required") from exc
        except CoordinatorSigningBindingError:
            raise
        except SigningJournalError as exc:
            raise SigningPersistenceError("signing_persistence_error") from exc
        except (ThresholdResolutionSignerError, VaultSignerError) as exc:
            raise SettlementSignerFailure("strict_2of2_signing_failed") from exc

        return AgreedSettlementSigningResult(
            coordinator_job_id=job.job_id,
            signing_intent_id=completed.signing_scope_id,
            signing_state=completed.state,
            canonical_message_digest=completed.canonical_message_digest,
            canonical_message=completed.canonical_message,
            signer_a_id=completed.signer_a.signer_id,
            signer_a_public_key=completed.signer_a.public_key,
            signer_a_key_version=completed.signer_a.key_version,
            signer_b_id=completed.signer_b.signer_id,
            signer_b_public_key=completed.signer_b.public_key,
            signer_b_key_version=completed.signer_b.key_version,
            signature_bundle=bundle,
        )

    def _load_signable_job(self, job_id: str) -> ResolutionJob:
        if not isinstance(job_id, str) or not job_id:
            raise CoordinatorJobMissing("coordinator_job_missing")
        try:
            job = self._coordinator_state.get_job(job_id)
        except CoordinatorRejected as exc:
            if str(exc) == "resolution_job_not_found":
                raise CoordinatorJobMissing("coordinator_job_missing") from exc
            raise CoordinatorSigningBindingError("coordinator_state_read_failed") from exc
        if job.state != AGREED:
            raise CoordinatorJobNotAgreed("coordinator_job_not_agreed")
        self._validate_agreed_binding(job, now_ms=self._clock_ms())
        return job

    @staticmethod
    def _validate_agreed_binding(job: ResolutionJob, *, now_ms: Optional[int] = None) -> None:
        if job.outcome not in ("YES", "NO", "INVALID"):
            raise CoordinatorSigningBindingError("agreed_outcome_invalid")
        if job.verifier_a_result is None or job.verifier_b_result is None:
            raise CoordinatorSigningBindingError("agreed_verifier_results_missing")
        for result, verifier in ((job.verifier_a_result, job.verifier_a), (job.verifier_b_result, job.verifier_b)):
            try:
                if result["definition_hash"] != job.resolver_definition_hash or result["evidence_hash"] != job.evidence_hash:
                    raise CoordinatorSigningBindingError("agreed_result_hash_binding_mismatch")
                if dict(result["verifier"]) != dict(verifier):
                    raise CoordinatorSigningBindingError("agreed_verifier_identity_mismatch")
            except (KeyError, TypeError) as exc:
                raise CoordinatorSigningBindingError("agreed_historical_record_malformed") from exc
        try:
            policy = AgreementPolicy(
                required_verifier_ids=(job.verifier_a["adapter_id"], job.verifier_b["adapter_id"]),
                required_verifier_count=2,
                minimum_agreeing_verifiers=2,
                exact_agreement=True,
            )
            for result in (job.verifier_a_result, job.verifier_b_result):
                resolver_v2.validate_verification_result(dict(result), now_ms=now_ms)
            decision = evaluate_agreement((job.verifier_a_result, job.verifier_b_result), policy, now_ms=now_ms)
        except (PipelineRejected, KeyError, TypeError, ValueError) as exc:
            raise CoordinatorSigningBindingError("agreed_historical_record_malformed") from exc
        if not decision.allowed or decision.canonical_outcome != job.outcome:
            raise CoordinatorSigningBindingError("agreed_state_binding_inconsistent")

    def _canonical_message(self, job: ResolutionJob) -> bytes:
        return canonical_message_for_agreed_job(self._coordinator_state, job)
