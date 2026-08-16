"""Phase 6D3 durable settlement submission and restart reconciliation.

Submission is explicit.  This module never changes coordinator/signing state and never
rebuilds/rebroadcasts an ambiguous transaction.  The exact signed bytes that passed
Phase 6D2 simulation are persisted before send and are the only bytes submitted.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from .settlement_rpc import (
    RpcSignatureStatus,
    RpcSimulationResult,
    SettlementRpcError,
    SettlementRpcResponseError,
    SettlementRpcTransportError,
)
from .runtime_config import ResolverRuntimeConfig
from .settlement_simulation import (
    READY_CANDIDATE,
    STALE_BLOCKHASH,
    SettlementSimulationRequest,
    SettlementSimulationResult,
    SettlementSimulationService,
)
from .settlement_submission_journal import (
    CONFIRMED,
    EXPIRED_UNSUBMITTED,
    FAILED_FINAL,
    PENDING,
    PREPARED,
    SIGNATURE_KNOWN,
    STATUS_UNKNOWN,
    SUBMISSION_STARTED,
    PreparedSettlementAttempt,
    SettlementAttemptJournal,
    SettlementAttemptJournalError,
    SettlementTransactionAttempt,
)
from .signing_journal import SigningJournal, SigningJournalError


_COMMITMENT_RANK = {"processed": 0, "confirmed": 1, "finalized": 2}


class SettlementSubmissionError(RuntimeError):
    pass


class SettlementSubmissionConfigError(SettlementSubmissionError):
    pass


class SettlementSubmissionBindingError(SettlementSubmissionError):
    pass


class SettlementSubmissionRpcError(SettlementSubmissionError):
    pass


class SettlementSubmissionSimulationRejected(SettlementSubmissionError):
    def __init__(self, status: str, program_error: str | None) -> None:
        super().__init__("settlement_simulation_not_ready")
        self.status = status
        self.program_error = program_error


class SettlementSubmissionExpiredUnsubmitted(SettlementSubmissionSimulationRejected):
    def __init__(self, program_error: str | None) -> None:
        super().__init__(EXPIRED_UNSUBMITTED, program_error)


@dataclass(frozen=True)
class SettlementExecutionResult:
    transaction_attempt_id: str
    coordinator_job_id: str
    signing_intent_id: str
    transaction_signature: str
    submission_state: str
    confirmation_status: str | None
    slot: int | None
    transaction_error: str | None
    failure_category: str | None
    canonical_settlement_digest: str
    transaction_digest: str


class _SubmissionRpc(Protocol):
    is_test_transport: bool

    def get_genesis_hash(self) -> str: ...

    def simulate_transaction(self, transaction: VersionedTransaction) -> RpcSimulationResult: ...

    def submit_exact_transaction(self, serialized_transaction: bytes) -> str: ...

    def get_signature_status(self, transaction_signature: str) -> RpcSignatureStatus: ...


class SettlementSubmissionService:
    """Fail-closed in-process boundary for one explicit settlement submission.

    A simulation service and signing journal are required only to create a brand-new
    transaction attempt.  Reconciliation of an existing durable attempt intentionally
    requires neither the fee-payer private key nor signing/Vault dependencies.
    """

    def __init__(
        self,
        *,
        attempt_journal: SettlementAttemptJournal,
        rpc: _SubmissionRpc,
        expected_genesis_hash: str,
        expected_cluster: str,
        expected_program_id: str,
        required_commitment: str,
        simulation_service: SettlementSimulationService | None = None,
        signing_journal: SigningJournal | None = None,
    ) -> None:
        if not isinstance(attempt_journal, SettlementAttemptJournal):
            raise SettlementSubmissionConfigError("settlement_attempt_journal_required")
        if required_commitment not in _COMMITMENT_RANK:
            raise SettlementSubmissionConfigError("settlement_confirmation_commitment_invalid")
        if not isinstance(expected_genesis_hash, str) or not expected_genesis_hash:
            raise SettlementSubmissionConfigError("settlement_expected_genesis_hash_invalid")
        if not isinstance(expected_cluster, str) or not expected_cluster:
            raise SettlementSubmissionConfigError("settlement_expected_cluster_invalid")
        try:
            if str(Pubkey.from_string(expected_program_id)) != expected_program_id:
                raise ValueError
        except Exception as exc:
            raise SettlementSubmissionConfigError("settlement_expected_program_id_invalid") from exc
        if simulation_service is not None:
            if not isinstance(simulation_service, SettlementSimulationService):
                raise SettlementSubmissionConfigError("settlement_simulation_service_invalid")
            if simulation_service.rpc_transport is not rpc:
                raise SettlementSubmissionConfigError("simulation_submission_rpc_identity_mismatch")
            if simulation_service.execution_config.expected_genesis_hash != expected_genesis_hash:
                raise SettlementSubmissionConfigError("simulation_submission_genesis_mismatch")
            if simulation_service.execution_config.rpc.commitment != required_commitment:
                raise SettlementSubmissionConfigError("simulation_submission_commitment_mismatch")
        if signing_journal is not None and not isinstance(signing_journal, SigningJournal):
            raise SettlementSubmissionConfigError("signing_journal_invalid")
        self._journal = attempt_journal
        self._rpc = rpc
        self._expected_genesis_hash = expected_genesis_hash
        self._expected_cluster = expected_cluster
        self._expected_program_id = expected_program_id
        self._required_commitment = required_commitment
        self._simulation = simulation_service
        self._signing_journal = signing_journal

    @classmethod
    def from_runtime_config(
        cls,
        *,
        runtime_config: ResolverRuntimeConfig,
        simulation_service: SettlementSimulationService | None,
        signing_journal: SigningJournal | None,
    ) -> "SettlementSubmissionService":
        if not isinstance(runtime_config, ResolverRuntimeConfig):
            raise SettlementSubmissionConfigError("validated_runtime_config_required")
        execution = runtime_config.settlement_execution
        if execution is None or not execution.journal_path:
            raise SettlementSubmissionConfigError("settlement_attempt_journal_path_required")
        path = Path(execution.journal_path)
        if runtime_config.environment == "public-devnet" and (
            execution.journal_path == ":memory:" or not path.is_absolute()
        ):
            raise SettlementSubmissionConfigError(
                "public_devnet_requires_persistent_attempt_journal"
            )
        if simulation_service is None:
            raise SettlementSubmissionConfigError(
                "runtime_bootstrap_requires_simulation_service"
            )
        return cls(
            attempt_journal=SettlementAttemptJournal(path),
            rpc=simulation_service.rpc_transport,
            expected_genesis_hash=execution.expected_genesis_hash,
            expected_cluster=execution.expected_cluster,
            expected_program_id=runtime_config.solana.prophet_program_id,
            required_commitment=execution.rpc.commitment,
            simulation_service=simulation_service,
            signing_journal=signing_journal,
        )

    def submit_settlement(self, coordinator_job_id: str) -> SettlementExecutionResult:
        """Submit or reconcile one settlement without blind resubmission."""
        self._validate_job_id(coordinator_job_id)
        existing = self._journal.find_for_job(coordinator_job_id)
        if existing is not None:
            return self._resume_existing(existing)

        if self._simulation is None or self._signing_journal is None:
            raise SettlementSubmissionConfigError("new_submission_dependencies_required")
        try:
            link = self._signing_journal.get_coordinator_link(coordinator_job_id)
        except SigningJournalError as exc:
            raise SettlementSubmissionBindingError("coordinator_signing_link_missing") from exc

        # Phase 6D2 owns trusted genesis validation, fresh blockhash acquisition,
        # 6D1 construction, fee-payer signing, and exact-candidate simulation.
        simulation = self._simulation.simulate(
            SettlementSimulationRequest(
                coordinator_job_id=coordinator_job_id,
                signing_intent_id=link.signing_scope_id,
            )
        )
        if simulation.status == STALE_BLOCKHASH:
            raise SettlementSubmissionExpiredUnsubmitted(simulation.program_error)
        if simulation.status != READY_CANDIDATE or not simulation.ready_for_submission:
            raise SettlementSubmissionSimulationRejected(
                simulation.status, simulation.program_error
            )

        prepared = self._prepared_from_simulation(simulation)
        try:
            attempt = self._journal.create_or_load_prepared(prepared)
        except SettlementAttemptJournalError as exc:
            raise SettlementSubmissionBindingError("settlement_attempt_persistence_failed") from exc

        # A concurrent caller may have won with another blockhash before our insert.
        # Only the durable winner is eligible for send. If it is not our exact
        # simulated candidate, reconcile/resume it instead of submitting ours.
        if attempt.transaction_digest != prepared.transaction_digest:
            return self._resume_existing(attempt)
        return self._send_prepared(attempt, genesis_already_validated=True)

    def reconcile_settlement(self, coordinator_job_id: str) -> SettlementExecutionResult:
        """One explicit read/reconciliation pass; never sends a transaction."""
        self._validate_job_id(coordinator_job_id)
        attempt = self._journal.find_for_job(coordinator_job_id)
        if attempt is None:
            raise SettlementSubmissionBindingError("settlement_attempt_not_found")
        if attempt.submission_state in {CONFIRMED, FAILED_FINAL, EXPIRED_UNSUBMITTED}:
            return self._result(attempt)
        if attempt.submission_state == PREPARED:
            # Definitely never submitted. Reconciliation itself is read-only and
            # does not promote PREPARED to a send state.
            return self._result(attempt)
        self._validate_rpc_genesis(attempt)
        return self._reconcile_active(attempt)

    def _resume_existing(self, attempt: SettlementTransactionAttempt) -> SettlementExecutionResult:
        if attempt.submission_state in {CONFIRMED, FAILED_FINAL, EXPIRED_UNSUBMITTED}:
            return self._result(attempt)
        if attempt.submission_state == PREPARED:
            # PREPARED proves no submission marker was committed. Re-simulate the
            # exact durable bytes on restart to catch blockhash expiry without
            # rebuilding/re-signing or acquiring a new blockhash.
            self._validate_rpc_genesis(attempt)
            try:
                transaction = VersionedTransaction.from_bytes(attempt.serialized_transaction)
                simulation = self._rpc.simulate_transaction(transaction)
            except SettlementRpcError as exc:
                raise SettlementSubmissionRpcError("prepared_candidate_resimulation_failed") from exc
            if simulation.program_error is not None:
                if self._is_stale_blockhash_error(simulation.program_error):
                    expired = self._journal.mark_expired_unsubmitted(attempt.attempt_id)
                    return self._result(expired)
                failed = self._journal.mark_failed_final(
                    attempt.attempt_id,
                    confirmation_status=None,
                    slot=None,
                    transaction_error=simulation.program_error,
                    failure_category="pre_submission_simulation_rejected",
                )
                return self._result(failed)
            return self._send_prepared(attempt, genesis_already_validated=True)

        # Any state at/after the durable submission marker MUST reconcile first.
        self._validate_rpc_genesis(attempt)
        return self._reconcile_active(attempt)

    def _send_prepared(
        self, attempt: SettlementTransactionAttempt, *, genesis_already_validated: bool
    ) -> SettlementExecutionResult:
        if not genesis_already_validated:
            self._validate_rpc_genesis(attempt)
        try:
            claimed, should_send = self._journal.begin_submission(attempt.attempt_id)
        except SettlementAttemptJournalError as exc:
            raise SettlementSubmissionBindingError("submission_marker_persistence_failed") from exc
        if not should_send:
            return self._resume_existing(claimed)

        # The SUBMISSION_STARTED commit above is the point of no blind resend.
        try:
            returned_signature = self._rpc.submit_exact_transaction(
                claimed.serialized_transaction
            )
        except SettlementRpcTransportError:
            unknown = self._journal.mark_status_unknown(
                claimed.attempt_id, "submission_transport_failure"
            )
            return self._result(unknown)
        except SettlementRpcError as exc:
            unknown = self._journal.mark_status_unknown(
                claimed.attempt_id, "submission_response_invalid"
            )
            raise SettlementSubmissionRpcError("submission_response_invalid") from exc

        try:
            parsed_signature = Signature.from_string(str(returned_signature))
            canonical_returned_signature = str(parsed_signature)
            if canonical_returned_signature != str(returned_signature):
                raise ValueError
        except Exception as exc:
            self._journal.mark_status_unknown(
                claimed.attempt_id, "rpc_signature_malformed"
            )
            raise SettlementSubmissionRpcError("rpc_transaction_signature_malformed") from exc
        if canonical_returned_signature != claimed.local_transaction_signature:
            self._journal.mark_status_unknown(
                claimed.attempt_id, "rpc_local_signature_mismatch"
            )
            raise SettlementSubmissionBindingError("rpc_local_transaction_signature_mismatch")
        try:
            known = self._journal.record_rpc_signature(
                claimed.attempt_id, returned_signature
            )
        except SettlementAttemptJournalError as exc:
            # RPC may already have accepted the transaction. The durable send marker
            # remains authoritative; do not attempt another send.
            try:
                self._journal.mark_status_unknown(
                    claimed.attempt_id, "signature_persistence_failure"
                )
            except SettlementAttemptJournalError:
                pass
            raise SettlementSubmissionBindingError("rpc_signature_persistence_failed") from exc
        return self._reconcile_active(known)

    def _reconcile_active(self, attempt: SettlementTransactionAttempt) -> SettlementExecutionResult:
        if attempt.submission_state == PREPARED:
            return self._result(attempt)
        if attempt.submission_state in {CONFIRMED, FAILED_FINAL, EXPIRED_UNSUBMITTED}:
            return self._result(attempt)
        try:
            status = self._rpc.get_signature_status(attempt.local_transaction_signature)
        except SettlementRpcTransportError:
            unknown = self._journal.mark_status_unknown(
                attempt.attempt_id, "signature_status_transport_failure"
            )
            return self._result(unknown)
        except SettlementRpcError as exc:
            try:
                self._journal.mark_status_unknown(
                    attempt.attempt_id, "signature_status_response_invalid"
                )
            except SettlementAttemptJournalError:
                pass
            raise SettlementSubmissionRpcError("signature_status_response_invalid") from exc

        if not status.found:
            if attempt.submission_state in {SUBMISSION_STARTED, STATUS_UNKNOWN, PENDING}:
                updated = self._journal.mark_status_unknown(
                    attempt.attempt_id, "signature_status_not_found"
                )
                return self._result(updated)
            # RPC returned a matching signature earlier; absence now is not proof
            # the transaction was never submitted, so retain SIGNATURE_KNOWN.
            return self._result(attempt)

        if status.slot is None or status.confirmation_status is None:
            try:
                self._journal.mark_status_unknown(
                    attempt.attempt_id, "signature_status_malformed"
                )
            except SettlementAttemptJournalError:
                pass
            raise SettlementSubmissionRpcError("signature_status_malformed")

        if status.transaction_error is not None:
            if self._meets_commitment(status.confirmation_status):
                failed = self._journal.mark_failed_final(
                    attempt.attempt_id,
                    confirmation_status=status.confirmation_status,
                    slot=status.slot,
                    transaction_error=status.transaction_error,
                    failure_category="landed_transaction_error",
                )
                return self._result(failed)
            pending_error = self._journal.mark_pending(
                attempt.attempt_id,
                confirmation_status=status.confirmation_status,
                slot=status.slot,
                transaction_error=status.transaction_error,
                failure_category="transaction_error_awaiting_commitment",
            )
            return self._result(pending_error)

        if self._meets_commitment(status.confirmation_status):
            confirmed = self._journal.mark_confirmed(
                attempt.attempt_id,
                confirmation_status=status.confirmation_status,
                slot=status.slot,
            )
            return self._result(confirmed)

        pending = self._journal.mark_pending(
            attempt.attempt_id,
            confirmation_status=status.confirmation_status,
            slot=status.slot,
        )
        return self._result(pending)

    def _validate_rpc_genesis(self, attempt: SettlementTransactionAttempt) -> None:
        if attempt.cluster != self._expected_cluster:
            raise SettlementSubmissionBindingError("attempt_runtime_cluster_mismatch")
        if attempt.program_id != self._expected_program_id:
            raise SettlementSubmissionBindingError("attempt_runtime_program_id_mismatch")
        if attempt.genesis_hash != self._expected_genesis_hash:
            raise SettlementSubmissionBindingError("attempt_runtime_genesis_mismatch")
        try:
            actual = self._rpc.get_genesis_hash()
        except SettlementRpcError as exc:
            raise SettlementSubmissionRpcError("rpc_genesis_validation_failed") from exc
        if actual != self._expected_genesis_hash:
            raise SettlementSubmissionBindingError("rpc_genesis_hash_mismatch")

    def _meets_commitment(self, actual: str) -> bool:
        if actual not in _COMMITMENT_RANK:
            raise SettlementSubmissionRpcError("signature_status_commitment_invalid")
        return _COMMITMENT_RANK[actual] >= _COMMITMENT_RANK[self._required_commitment]

    @staticmethod
    def _prepared_from_simulation(
        simulation: SettlementSimulationResult,
    ) -> PreparedSettlementAttempt:
        artifact = simulation.transaction
        signatures = artifact.transaction_signatures
        if len(signatures) != 1:
            raise SettlementSubmissionBindingError("local_transaction_signature_invalid")
        if artifact.transaction_digest != hashlib.sha256(
            artifact.serialized_transaction
        ).hexdigest():
            raise SettlementSubmissionBindingError("simulated_transaction_digest_mismatch")
        return PreparedSettlementAttempt(
            coordinator_job_id=artifact.coordinator_job_id,
            signing_intent_id=artifact.signing_intent_id,
            canonical_settlement_digest=artifact.canonical_message_digest,
            serialized_transaction=artifact.serialized_transaction,
            transaction_digest=artifact.transaction_digest,
            fee_payer_pubkey=artifact.fee_payer_pubkey,
            recent_blockhash=artifact.recent_blockhash,
            program_id=artifact.program_id,
            cluster=artifact.cluster,
            genesis_hash=artifact.genesis_hash,
            local_transaction_signature=signatures[0],
        )

    @staticmethod
    def _result(attempt: SettlementTransactionAttempt) -> SettlementExecutionResult:
        return SettlementExecutionResult(
            transaction_attempt_id=attempt.attempt_id,
            coordinator_job_id=attempt.coordinator_job_id,
            signing_intent_id=attempt.signing_intent_id,
            transaction_signature=attempt.local_transaction_signature,
            submission_state=attempt.submission_state,
            confirmation_status=attempt.confirmation_status,
            slot=attempt.slot,
            transaction_error=attempt.transaction_error,
            failure_category=attempt.failure_category,
            canonical_settlement_digest=attempt.canonical_settlement_digest,
            transaction_digest=attempt.transaction_digest,
        )

    @staticmethod
    def _validate_job_id(value: str) -> None:
        if not isinstance(value, str) or not value:
            raise SettlementSubmissionBindingError("coordinator_job_id_invalid")

    @staticmethod
    def _is_stale_blockhash_error(error: str) -> bool:
        normalized = error.replace("_", " ").replace("-", " ").lower()
        return (
            "blockhashnotfound" in normalized.replace(" ", "")
            or "blockhash not found" in normalized
        )
