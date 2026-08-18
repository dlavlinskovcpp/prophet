import hashlib
import importlib.metadata
import inspect
from dataclasses import FrozenInstanceError

import pytest
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from src.settlement_rpc import (
    RpcSignatureStatus,
    RpcSimulationResult,
    SettlementRpcResponseError,
    SettlementRpcTransportError,
)
from src.settlement_submission import (
    SettlementExecutionResult,
    SettlementSubmissionBindingError,
    SettlementSubmissionExpiredUnsubmitted,
    SettlementSubmissionRpcError,
    SettlementSubmissionService,
    SettlementSubmissionSimulationRejected,
)
from src.settlement_submission_journal import (
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
    SettlementAttemptJournalBindingError,
    SettlementAttemptJournalStateError,
)
from tests.test_settlement_simulation import (
    FakeSettlementRpc,
    PROGRAM_REJECTED,
    STALE_BLOCKHASH,
    _service as simulation_setup,
    _state_snapshot,
)
from tests.test_settlement_transaction_construction import BLOCKHASH_2, GENESIS_HASH, PROGRAM_ID


class FakeSubmissionRpc(FakeSettlementRpc):
    """Deterministic test-only 6D3 RPC with explicit send/status accounting."""

    def __init__(
        self,
        *,
        status=None,
        send_mode="ok",
        returned_signature=None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.status = status or RpcSignatureStatus(True, 77, "confirmed", None)
        self.send_mode = send_mode
        self.returned_signature = returned_signature
        self.submitted_bytes = []
        self.status_calls = 0

    def submit_exact_transaction(self, serialized_transaction):
        self.calls.append("send")
        self.send_calls += 1
        if self.send_mode == "fail_before_receive":
            raise SettlementRpcTransportError("drop-before-receive")
        self.submitted_bytes.append(bytes(serialized_transaction))
        if self.send_mode == "fail_after_receive":
            raise SettlementRpcTransportError("drop-after-receive")
        tx = VersionedTransaction.from_bytes(bytes(serialized_transaction))
        local_signature = str(tuple(tx.signatures)[0])
        return self.returned_signature or local_signature

    def get_signature_status(self, transaction_signature):
        self.calls.append("status")
        self.status_calls += 1
        if self.fail_at == "status":
            raise SettlementRpcTransportError("status-down")
        if self.fail_at == "status_malformed":
            raise SettlementRpcResponseError("status-malformed")
        # Fake still validates that reconciliation uses the deterministic local tx id.
        Signature.from_string(transaction_signature)
        return self.status


def _execution(tmp_path, monkeypatch, *, rpc=None, seed=41):
    rpc = rpc or FakeSubmissionRpc()
    x, signer, rpc, simulation, request = simulation_setup(
        tmp_path, monkeypatch, rpc=rpc, seed=seed
    )
    attempts = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    service = SettlementSubmissionService(
        attempt_journal=attempts,
        rpc=rpc,
        expected_genesis_hash=GENESIS_HASH,
        expected_cluster="localnet",
        expected_program_id=PROGRAM_ID,
        required_commitment="confirmed",
        simulation_service=simulation,
        signing_journal=x["journal"],
    )
    return x, signer, rpc, simulation, request, attempts, service


def _prepared(simulation, request):
    result = simulation.simulate(request)
    prepared = SettlementSubmissionService._prepared_from_simulation(result)
    return result, prepared


def _recovery_service(attempts, rpc):
    return SettlementSubmissionService(
        attempt_journal=attempts,
        rpc=rpc,
        expected_genesis_hash=GENESIS_HASH,
        expected_cluster="localnet",
        expected_program_id=PROGRAM_ID,
        required_commitment="confirmed",
        simulation_service=None,
        signing_journal=None,
    )


def _attempt_rows(journal):
    return tuple(
        tuple(row)
        for row in journal._db.execute(
            "SELECT * FROM settlement_transaction_attempts ORDER BY rowid"
        ).fetchall()
    )


def test_01_successful_candidate_is_persisted_sent_once_and_confirmed(tmp_path, monkeypatch):
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch)
    before = _state_snapshot(x)
    result = service.submit_settlement(x["job"].job_id)
    assert isinstance(result, SettlementExecutionResult)
    assert result.submission_state == CONFIRMED
    assert result.confirmation_status == "confirmed"
    assert result.slot == 77
    assert rpc.send_calls == 1
    assert rpc.calls == ["genesis", "blockhash", "simulate", "send", "status"]
    assert _state_snapshot(x) == before
    assert attempts.get(result.transaction_attempt_id).submission_state == CONFIRMED


def test_02_attempt_is_durable_before_send(tmp_path, monkeypatch):
    x, _signer, rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    attempt = attempts.create_or_load_prepared(prepared)
    assert attempt.submission_state == PREPARED
    assert rpc.send_calls == 0
    claimed, should_send = attempts.begin_submission(attempt.attempt_id)
    assert should_send is True
    assert claimed.submission_state == SUBMISSION_STARTED
    assert rpc.send_calls == 0


def test_03_exact_submitted_bytes_equal_simulated_and_durable_bytes(tmp_path, monkeypatch):
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch)
    result = service.submit_settlement(x["job"].job_id)
    attempt = attempts.get(result.transaction_attempt_id)
    assert len(rpc.submitted_bytes) == 1
    assert rpc.submitted_bytes[0] == rpc.simulated_bytes == attempt.serialized_transaction
    assert hashlib.sha256(rpc.submitted_bytes[0]).hexdigest() == attempt.transaction_digest


def test_04_rpc_returned_signature_equals_local_transaction_signature(tmp_path, monkeypatch):
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch)
    result = service.submit_settlement(x["job"].job_id)
    attempt = attempts.get(result.transaction_attempt_id)
    tx = VersionedTransaction.from_bytes(attempt.serialized_transaction)
    assert result.transaction_signature == str(tuple(tx.signatures)[0])
    assert result.transaction_signature == attempt.local_transaction_signature


def test_05_repeated_confirmed_call_makes_zero_additional_send_blockhash_or_build(tmp_path, monkeypatch):
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch)
    first = service.submit_settlement(x["job"].job_id)
    calls = list(rpc.calls)
    second = service.submit_settlement(x["job"].job_id)
    assert second == first
    assert rpc.calls == calls
    assert rpc.send_calls == 1


def test_06_transport_failure_before_rpc_receives_bytes_is_status_unknown(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_before_receive")
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    result = service.submit_settlement(x["job"].job_id)
    assert result.submission_state == STATUS_UNKNOWN
    assert result.failure_category == "submission_transport_failure"
    assert rpc.send_calls == 1
    assert rpc.submitted_bytes == []
    assert attempts.get(result.transaction_attempt_id).submission_state == STATUS_UNKNOWN


def test_07_ambiguous_send_after_rpc_receives_bytes_never_blindly_resubmits(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    first = service.submit_settlement(x["job"].job_id)
    assert first.submission_state == STATUS_UNKNOWN
    assert len(rpc.submitted_bytes) == 1
    rpc.send_mode = "ok"
    rpc.status = RpcSignatureStatus(False, None, None, None)
    second = service.submit_settlement(x["job"].job_id)
    assert second.submission_state == STATUS_UNKNOWN
    assert rpc.send_calls == 1
    assert rpc.status_calls == 1


def test_08_ambiguous_send_later_confirmed_without_second_send(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    first = service.submit_settlement(x["job"].job_id)
    assert first.submission_state == STATUS_UNKNOWN
    rpc.send_mode = "ok"
    rpc.status = RpcSignatureStatus(True, 88, "confirmed", None)
    second = service.submit_settlement(x["job"].job_id)
    assert second.submission_state == CONFIRMED
    assert second.slot == 88
    assert rpc.send_calls == 1
    assert attempts.get(second.transaction_attempt_id).submission_state == CONFIRMED


def test_09_ambiguous_send_later_landed_program_failure_is_terminal(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    first = service.submit_settlement(x["job"].job_id)
    rpc.status = RpcSignatureStatus(True, 89, "confirmed", "InstructionError(2, Custom(6001))")
    failed = service.submit_settlement(x["job"].job_id)
    assert first.submission_state == STATUS_UNKNOWN
    assert failed.submission_state == FAILED_FINAL
    assert failed.failure_category == "landed_transaction_error"
    assert rpc.send_calls == 1
    again = service.submit_settlement(x["job"].job_id)
    assert again == failed
    assert rpc.send_calls == 1
    assert attempts.get(failed.transaction_attempt_id).transaction_error is not None


def test_10_rpc_signature_mismatch_fails_closed_and_never_resends(tmp_path, monkeypatch):
    wrong = str(Signature.from_bytes(bytes([9]) * 64))
    rpc = FakeSubmissionRpc(returned_signature=wrong)
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementSubmissionBindingError, match="rpc_local_transaction_signature_mismatch"):
        service.submit_settlement(x["job"].job_id)
    attempt = attempts.get_for_job(x["job"].job_id)
    assert attempt.submission_state == STATUS_UNKNOWN
    assert rpc.send_calls == 1
    rpc.returned_signature = None
    rpc.status = RpcSignatureStatus(False, None, None, None)
    service.submit_settlement(x["job"].job_id)
    assert rpc.send_calls == 1


def test_11_malformed_rpc_signature_fails_closed(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(returned_signature="not-a-solana-signature")
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementSubmissionRpcError, match="rpc_transaction_signature_malformed"):
        service.submit_settlement(x["job"].job_id)
    assert attempts.get_for_job(x["job"].job_id).submission_state == STATUS_UNKNOWN
    assert rpc.send_calls == 1


def test_12_malformed_status_response_fails_closed_and_persists_unknown(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(fail_at="status_malformed")
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementSubmissionRpcError, match="signature_status_response_invalid"):
        service.submit_settlement(x["job"].job_id)
    attempt = attempts.get_for_job(x["job"].job_id)
    assert attempt.submission_state == STATUS_UNKNOWN
    assert rpc.send_calls == 1


def test_13_status_transport_failure_is_unknown_and_no_resubmit(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(fail_at="status")
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    result = service.submit_settlement(x["job"].job_id)
    assert result.submission_state == STATUS_UNKNOWN
    assert result.failure_category == "signature_status_transport_failure"
    rpc.fail_at = None
    rpc.status = RpcSignatureStatus(False, None, None, None)
    service.submit_settlement(x["job"].job_id)
    assert rpc.send_calls == 1


def test_14_pending_status_is_not_confirmation_and_is_not_resubmitted(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(status=RpcSignatureStatus(True, 90, "processed", None))
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    result = service.submit_settlement(x["job"].job_id)
    assert result.submission_state == PENDING
    assert result.confirmation_status == "processed"
    assert rpc.send_calls == 1
    service.submit_settlement(x["job"].job_id)
    assert rpc.send_calls == 1


def test_15_finalized_satisfies_confirmed_commitment(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(status=RpcSignatureStatus(True, 91, "finalized", None))
    x, _signer, _rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    result = service.submit_settlement(x["job"].job_id)
    assert result.submission_state == CONFIRMED
    assert result.confirmation_status == "finalized"


def test_16_wrong_rpc_genesis_rejects_before_new_attempt_or_send(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(genesis_hash=BLOCKHASH_2)
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(Exception, match="genesis_hash_mismatch"):
        service.submit_settlement(x["job"].job_id)
    assert attempts.find_for_job(x["job"].job_id) is None
    assert rpc.send_calls == 0
    assert rpc.calls == ["genesis"]


def test_17_incomplete_or_uncertain_signing_rejects_before_attempt_and_send(tmp_path, monkeypatch):
    from tests.test_settlement_transaction_construction import _setup as construction_setup
    for mode in ("intent", "uncertain"):
        x = construction_setup(tmp_path / mode, monkeypatch, signing_mode=mode)
        rpc = FakeSubmissionRpc()
        from src.settlement_simulation import SettlementSimulationService, SettlementSimulationRequest
        from tests.test_settlement_simulation import _execution_config, CountingFeePayerSigner
        from solders.keypair import Keypair
        simulation = SettlementSimulationService(
            builder=x["builder"], solana_runtime=x["runtime"], execution_config=_execution_config(x["runtime"]),
            fee_payer_signer=CountingFeePayerSigner(Keypair.from_seed(bytes([41]) * 32)), rpc=rpc,
            environment="localtest", mode="test",
        )
        attempts = SettlementAttemptJournal(tmp_path / f"{mode}-attempts.sqlite")
        service = SettlementSubmissionService(
            attempt_journal=attempts, rpc=rpc, expected_genesis_hash=GENESIS_HASH,
            expected_cluster="localnet", expected_program_id=PROGRAM_ID,
            required_commitment="confirmed", simulation_service=simulation, signing_journal=x["journal"],
        )
        with pytest.raises(Exception):
            service.submit_settlement(x["job"].job_id)
        assert attempts.find_for_job(x["job"].job_id) is None
        assert rpc.send_calls == 0


def test_18_conflict_or_partial_job_rejects_before_send(tmp_path, monkeypatch):
    from tests.test_settlement_transaction_construction import _setup as construction_setup
    from src.settlement_simulation import SettlementSimulationService
    from tests.test_settlement_simulation import _execution_config, CountingFeePayerSigner
    from solders.keypair import Keypair
    for terminal in ("CONFLICT", "PARTIAL"):
        x = construction_setup(tmp_path / terminal, monkeypatch, terminal=terminal)
        rpc = FakeSubmissionRpc()
        simulation = SettlementSimulationService(
            builder=x["builder"], solana_runtime=x["runtime"], execution_config=_execution_config(x["runtime"]),
            fee_payer_signer=CountingFeePayerSigner(Keypair.from_seed(bytes([42]) * 32)), rpc=rpc,
            environment="localtest", mode="test",
        )
        attempts = SettlementAttemptJournal(tmp_path / f"{terminal}-attempts.sqlite")
        service = SettlementSubmissionService(
            attempt_journal=attempts, rpc=rpc, expected_genesis_hash=GENESIS_HASH,
            expected_cluster="localnet", expected_program_id=PROGRAM_ID,
            required_commitment="confirmed", simulation_service=simulation, signing_journal=x["journal"],
        )
        with pytest.raises(Exception):
            service.submit_settlement(x["job"].job_id)
        assert rpc.send_calls == 0
        assert attempts.find_for_job(x["job"].job_id) is None


def test_19_stale_blockhash_simulation_before_attempt_means_zero_send(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(
        simulation=RpcSimulationResult("BlockhashNotFound", ("stale",), 100, None, None)
    )
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementSubmissionExpiredUnsubmitted) as exc:
        service.submit_settlement(x["job"].job_id)
    assert exc.value.status == EXPIRED_UNSUBMITTED
    assert attempts.find_for_job(x["job"].job_id) is None
    assert rpc.send_calls == 0


def test_20_program_error_simulation_before_attempt_means_zero_send(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(
        simulation=RpcSimulationResult(
            "InstructionError(2, Custom(6001))", ("Prophet failed",), 100, None, None
        )
    )
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementSubmissionSimulationRejected):
        service.submit_settlement(x["job"].job_id)
    assert attempts.find_for_job(x["job"].job_id) is None
    assert rpc.send_calls == 0


def test_21_restart_after_prepared_resimulates_exact_durable_bytes_then_sends(tmp_path, monkeypatch):
    x, _signer, rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    sim, prepared = _prepared(simulation, request)
    attempt = attempts.create_or_load_prepared(prepared)
    expected = attempt.serialized_transaction
    attempts.close()
    reopened = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    recovery = _recovery_service(reopened, rpc)
    rpc.calls.clear()
    rpc.simulated_bytes = None
    result = recovery.submit_settlement(x["job"].job_id)
    assert result.submission_state == CONFIRMED
    assert rpc.calls == ["genesis", "simulate", "send", "status"]
    assert rpc.simulated_bytes == expected
    assert rpc.submitted_bytes[-1] == expected == sim.transaction.serialized_transaction


def test_22_restart_after_prepared_with_expired_blockhash_never_sends(tmp_path, monkeypatch):
    x, _signer, rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    attempts.create_or_load_prepared(prepared)
    attempts.close()
    reopened = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    rpc.simulation = RpcSimulationResult("BlockhashNotFound", ("stale",), 100, None, None)
    rpc.calls.clear()
    recovery = _recovery_service(reopened, rpc)
    result = recovery.submit_settlement(x["job"].job_id)
    assert result.submission_state == EXPIRED_UNSUBMITTED
    assert rpc.send_calls == 0
    assert rpc.calls == ["genesis", "simulate"]


def test_23_restart_after_submission_marker_reconciles_before_any_send(tmp_path, monkeypatch):
    x, _signer, rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    attempt = attempts.create_or_load_prepared(prepared)
    attempts.begin_submission(attempt.attempt_id)
    attempts.close()
    reopened = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    rpc.status = RpcSignatureStatus(False, None, None, None)
    rpc.calls.clear()
    recovery = _recovery_service(reopened, rpc)
    result = recovery.submit_settlement(x["job"].job_id)
    assert result.submission_state == STATUS_UNKNOWN
    assert rpc.calls == ["genesis", "status"]
    assert rpc.send_calls == 0


def test_24_restart_after_signature_known_reconciles_without_fee_payer_key(tmp_path, monkeypatch):
    x, _signer, rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    attempt = attempts.create_or_load_prepared(prepared)
    attempt, claimed = attempts.begin_submission(attempt.attempt_id)
    assert claimed
    attempts.record_rpc_signature(attempt.attempt_id, attempt.local_transaction_signature)
    attempts.close()
    reopened = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    rpc.status = RpcSignatureStatus(True, 100, "confirmed", None)
    recovery = _recovery_service(reopened, rpc)
    result = recovery.submit_settlement(x["job"].job_id)
    assert result.submission_state == CONFIRMED
    assert rpc.send_calls == 0


def test_25_restart_after_confirmed_returns_durable_success_without_rpc(tmp_path, monkeypatch):
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch)
    first = service.submit_settlement(x["job"].job_id)
    attempts.close()
    reopened = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    rpc.calls.clear()
    recovery = _recovery_service(reopened, rpc)
    second = recovery.submit_settlement(x["job"].job_id)
    assert second == first
    assert rpc.calls == []
    assert rpc.send_calls == 1


def test_26_status_reconciliation_does_not_require_signing_or_fee_payer_objects(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    unknown = service.submit_settlement(x["job"].job_id)
    attempts.close()
    reopened = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    rpc.status = RpcSignatureStatus(True, 101, "confirmed", None)
    recovery = _recovery_service(reopened, rpc)
    confirmed = recovery.reconcile_settlement(x["job"].job_id)
    assert unknown.submission_state == STATUS_UNKNOWN
    assert confirmed.submission_state == CONFIRMED
    assert rpc.send_calls == 1


def test_27_ambiguous_send_blockhash_expiry_does_not_trigger_rebuild_or_resend(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    unknown = service.submit_settlement(x["job"].job_id)
    digest = unknown.transaction_digest
    rpc.simulation = RpcSimulationResult("BlockhashNotFound", ("stale",), 1, None, None)
    rpc.status = RpcSignatureStatus(False, None, None, None)
    again = service.submit_settlement(x["job"].job_id)
    assert again.submission_state == STATUS_UNKNOWN
    assert again.transaction_digest == digest
    assert rpc.send_calls == 1


def test_28_duplicate_attempt_creation_resolves_to_one_durable_candidate(tmp_path, monkeypatch):
    x, _signer, _rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    first = attempts.create_or_load_prepared(prepared)
    second = attempts.create_or_load_prepared(prepared)
    assert first == second
    assert len(_attempt_rows(attempts)) == 1
    claimed, one = attempts.begin_submission(first.attempt_id)
    again, two = attempts.begin_submission(first.attempt_id)
    assert claimed.submission_state == SUBMISSION_STARTED
    assert again.submission_state == SUBMISSION_STARTED
    assert one is True and two is False


def test_29_concurrent_candidate_with_different_blockhash_cannot_compete(tmp_path, monkeypatch):
    x, signer, rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim1, prepared1 = _prepared(simulation, request)
    first = attempts.create_or_load_prepared(prepared1)
    rpc.blockhash = BLOCKHASH_2
    sim2 = simulation.simulate(request)
    prepared2 = SettlementSubmissionService._prepared_from_simulation(sim2)
    second = attempts.create_or_load_prepared(prepared2)
    assert second.attempt_id == first.attempt_id
    assert second.transaction_digest == first.transaction_digest
    assert second.recent_blockhash != BLOCKHASH_2
    assert signer.sign_calls == 2


def test_30_crash_after_rpc_return_before_signature_persistence_reconciles_without_second_send(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc()
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    original = attempts.record_rpc_signature
    def crash(*_args, **_kwargs):
        raise SettlementAttemptJournalStateError("injected-crash")
    attempts.record_rpc_signature = crash
    with pytest.raises(SettlementSubmissionBindingError, match="rpc_signature_persistence_failed"):
        service.submit_settlement(x["job"].job_id)
    attempts.record_rpc_signature = original
    assert rpc.send_calls == 1
    attempt = attempts.get_for_job(x["job"].job_id)
    assert attempt.submission_state == STATUS_UNKNOWN
    rpc.status = RpcSignatureStatus(True, 102, "confirmed", None)
    result = service.submit_settlement(x["job"].job_id)
    assert result.submission_state == CONFIRMED
    assert rpc.send_calls == 1


def test_31_confirmation_lookup_failure_after_signature_persistence_never_sends_again(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(fail_at="status")
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    first = service.submit_settlement(x["job"].job_id)
    assert first.submission_state == STATUS_UNKNOWN
    rpc.fail_at = None
    rpc.status = RpcSignatureStatus(True, 103, "confirmed", None)
    second = service.submit_settlement(x["job"].job_id)
    assert second.submission_state == CONFIRMED
    assert rpc.send_calls == 1


def test_32_zero_vault_calls_during_submit_and_reconcile(tmp_path, monkeypatch):
    x, _signer, _rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch)
    before = len(x["transport"].calls)
    monkeypatch.setattr(
        x["transport"], "sign_versioned",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("Vault called")),
    )
    service.submit_settlement(x["job"].job_id)
    service.submit_settlement(x["job"].job_id)
    assert len(x["transport"].calls) == before == 2


def test_33_no_verifier_calls_or_coordinator_mutation(tmp_path, monkeypatch):
    x, _signer, _rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch)
    before = _state_snapshot(x)
    # Phase 6D3 has no verifier client dependency at all.
    params = inspect.signature(SettlementSubmissionService.__init__).parameters
    assert not any("verifier" in name for name in params)
    service.submit_settlement(x["job"].job_id)
    assert _state_snapshot(x) == before


def test_34_signing_journal_rows_remain_byte_for_byte_unchanged(tmp_path, monkeypatch):
    x, _signer, _rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch)
    before_intents = tuple(tuple(r) for r in x["journal"]._db.execute("SELECT * FROM signing_intents ORDER BY rowid"))
    before_links = tuple(tuple(r) for r in x["journal"]._db.execute("SELECT * FROM coordinator_signing_links ORDER BY rowid"))
    service.submit_settlement(x["job"].job_id)
    after_intents = tuple(tuple(r) for r in x["journal"]._db.execute("SELECT * FROM signing_intents ORDER BY rowid"))
    after_links = tuple(tuple(r) for r in x["journal"]._db.execute("SELECT * FROM coordinator_signing_links ORDER BY rowid"))
    assert after_intents == before_intents
    assert after_links == before_links


def test_35_attempt_row_tampering_fails_closed(tmp_path, monkeypatch):
    x, _signer, _rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    attempt = attempts.create_or_load_prepared(prepared)
    attempts._db.execute(
        "UPDATE settlement_transaction_attempts SET transaction_digest = ? WHERE attempt_id = ?",
        ("00" * 32, attempt.attempt_id),
    )
    with pytest.raises(SettlementAttemptJournalBindingError):
        attempts.get(attempt.attempt_id)


def test_36_attempt_bytes_roundtrip_and_real_solders_021(tmp_path, monkeypatch):
    assert importlib.metadata.version("solders") == "0.21.0"
    x, _signer, _rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch)
    result = service.submit_settlement(x["job"].job_id)
    attempt = attempts.get(result.transaction_attempt_id)
    tx = VersionedTransaction.from_bytes(attempt.serialized_transaction)
    assert bytes(tx) == attempt.serialized_transaction
    assert isinstance(tuple(tx.signatures)[0], Signature)
    assert str(tuple(tx.signatures)[0]) == attempt.local_transaction_signature
    assert tuple(tx.verify_with_results()) == (True,)


def test_37_execution_result_is_immutable_and_contains_no_private_material(tmp_path, monkeypatch):
    x, _signer, _rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch)
    result = service.submit_settlement(x["job"].job_id)
    with pytest.raises(FrozenInstanceError):
        result.submission_state = "evil"
    fields = set(result.__dataclass_fields__)
    assert not any("private" in field or "secret" in field or "token" in field for field in fields)


def test_38_public_service_surface_has_no_auto_worker_or_generic_rpc(tmp_path, monkeypatch):
    public = {
        name
        for name, member in inspect.getmembers(SettlementSubmissionService, callable)
        if not name.startswith("_")
    }
    assert public == {"from_runtime_config", "reconcile_settlement", "submit_settlement"}
    assert not any("worker" in name or "auto" in name or "retry" in name for name in public)


def test_39_reconcile_prepared_is_read_only_and_does_not_send(tmp_path, monkeypatch):
    x, _signer, rpc, simulation, request, attempts, service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    attempt = attempts.create_or_load_prepared(prepared)
    before = _attempt_rows(attempts)
    result = service.reconcile_settlement(x["job"].job_id)
    assert result.submission_state == PREPARED
    assert _attempt_rows(attempts) == before
    assert rpc.send_calls == 0
    assert attempts.get(attempt.attempt_id).submission_state == PREPARED


def test_40_unknown_status_absence_is_not_proof_of_non_submission(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    first = service.submit_settlement(x["job"].job_id)
    rpc.status = RpcSignatureStatus(False, None, None, None)
    for _ in range(3):
        result = service.reconcile_settlement(x["job"].job_id)
        assert result.submission_state == STATUS_UNKNOWN
    assert first.submission_state == STATUS_UNKNOWN
    assert rpc.send_calls == 1


def test_41_landed_failure_does_not_return_to_ready_state(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(status=RpcSignatureStatus(True, 110, "confirmed", "Custom(1)"))
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    failed = service.submit_settlement(x["job"].job_id)
    assert failed.submission_state == FAILED_FINAL
    rpc.status = RpcSignatureStatus(True, 111, "finalized", None)
    again = service.submit_settlement(x["job"].job_id)
    assert again == failed
    assert rpc.send_calls == 1


def test_42_attempt_journal_rejects_malformed_transaction_identity(tmp_path, monkeypatch):
    _x, _signer, _rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    bad = PreparedSettlementAttempt(
        **{**prepared.__dict__, "transaction_digest": "00" * 32}
    )
    with pytest.raises(SettlementAttemptJournalBindingError, match="transaction_digest_mismatch"):
        attempts.create_or_load_prepared(bad)


def test_43_phase_6d3_does_not_change_resolution_authorization_bytes(tmp_path, monkeypatch):
    x, _signer, _rpc, simulation, request, attempts, service = _execution(tmp_path, monkeypatch)
    sim = simulation.simulate(request)
    before = (
        sim.transaction.canonical_message,
        sim.transaction.canonical_message_digest,
        sim.transaction.signer_a_signature,
        sim.transaction.signer_b_signature,
    )
    result = service.submit_settlement(x["job"].job_id)
    attempt = attempts.get(result.transaction_attempt_id)
    tx = VersionedTransaction.from_bytes(attempt.serialized_transaction)
    assert tuple(tx.verify_with_results()) == (True,)
    intent = x["journal"].get(result.signing_intent_id)
    after = (
        intent.canonical_message,
        intent.canonical_message_digest,
        intent.signer_a_result.signature,
        intent.signer_b_result.signature,
    )
    assert after == before


def test_44_runtime_config_journal_path_is_optional_for_6d2_but_available_for_6d3(tmp_path):
    from src.runtime_config import SolanaRuntimeConfig, parse_settlement_execution_config
    runtime = SolanaRuntimeConfig("localnet", GENESIS_HASH, "11111111111111111111111111111111")
    raw = {
        "rpc_url_env": "PROPHET_TEST_RPC_URL",
        "expected_cluster": "localnet",
        "expected_genesis_hash": GENESIS_HASH,
        "fee_payer": {"keypair_path_env": "PROPHET_TEST_FEE_PAYER_KEYPAIR_PATH"},
        "rpc": {"timeout_seconds": 10, "commitment": "confirmed"},
        "journal_path": str(tmp_path / "attempts.sqlite3"),
    }
    parsed = parse_settlement_execution_config(raw, solana=runtime)
    assert parsed.journal_path == raw["journal_path"]
    without = dict(raw)
    without.pop("journal_path")
    assert parse_settlement_execution_config(without, solana=runtime).journal_path is None


def test_45_preflight_and_node_rebroadcast_policy_is_explicit_in_rpc_wrapper(monkeypatch):
    from src.settlement_rpc import SolanaSettlementRpcClient
    captured = {}
    class RawClient:
        def __init__(self, *_args, **_kwargs): pass
        def send_raw_transaction(self, raw, opts):
            captured["raw"] = raw
            captured["opts"] = opts
            tx = VersionedTransaction.from_bytes(raw)
            return type("R", (), {"value": tuple(tx.signatures)[0]})()
    monkeypatch.setattr("src.settlement_rpc.Client", RawClient)
    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.message import MessageV0
    payer = Keypair.from_seed(bytes([70]) * 32)
    message = MessageV0.try_compile(payer.pubkey(), [], [], Hash.from_string(BLOCKHASH_2))
    tx = VersionedTransaction(message, [payer])
    rpc = SolanaSettlementRpcClient("https://rpc.example.invalid", timeout_seconds=10, commitment="confirmed")
    returned = rpc.submit_exact_transaction(bytes(tx))
    assert returned == str(tuple(tx.signatures)[0])
    assert captured["raw"] == bytes(tx)
    assert captured["opts"].skip_preflight is True
    assert captured["opts"].skip_confirmation is True
    assert captured["opts"].max_retries == 0


def test_46_rpc_status_wrapper_strictly_parses_found_and_missing(monkeypatch):
    from src.settlement_rpc import SolanaSettlementRpcClient
    signature = Signature.from_bytes(bytes([5]) * 64)
    class RawClient:
        def __init__(self, *_args, **_kwargs): self.mode = "found"
        def get_signature_statuses(self, signatures, search_transaction_history):
            assert signatures == [signature]
            assert search_transaction_history is True
            if self.mode == "missing":
                return type("R", (), {"value": [None]})()
            item = type("S", (), {"slot": 12, "confirmation_status": "confirmed", "err": None})()
            return type("R", (), {"value": [item]})()
    monkeypatch.setattr("src.settlement_rpc.Client", RawClient)
    rpc = SolanaSettlementRpcClient("https://rpc.example.invalid", timeout_seconds=10, commitment="confirmed")
    found = rpc.get_signature_status(str(signature))
    assert found == RpcSignatureStatus(True, 12, "confirmed", None)
    rpc._client.mode = "missing"
    assert rpc.get_signature_status(str(signature)) == RpcSignatureStatus(False, None, None, None)


def test_47_rpc_status_wrapper_rejects_malformed_shape(monkeypatch):
    from src.settlement_rpc import SolanaSettlementRpcClient
    signature = str(Signature.from_bytes(bytes([6]) * 64))
    class RawClient:
        def __init__(self, *_args, **_kwargs): pass
        def get_signature_statuses(self, *_args, **_kwargs):
            return type("R", (), {"value": []})()
    monkeypatch.setattr("src.settlement_rpc.Client", RawClient)
    rpc = SolanaSettlementRpcClient("https://rpc.example.invalid", timeout_seconds=10, commitment="confirmed")
    with pytest.raises(SettlementRpcResponseError, match="status_response_invalid"):
        rpc.get_signature_status(signature)


def test_48_no_automatic_submission_from_simulation_service():
    from src.settlement_simulation import SettlementSimulationService
    public = {
        name
        for name, member in inspect.getmembers(SettlementSimulationService, callable)
        if not name.startswith("_")
    }
    assert "submit" not in public
    assert "submit_settlement" not in public


def test_49_no_background_or_confirmation_poll_loop_in_submission_api():
    source = inspect.getsource(SettlementSubmissionService)
    assert "while True" not in source
    assert "send_raw_transaction" not in source
    assert "sendTransaction" not in source
    assert "background" not in source.lower()


def test_50_attempt_state_machine_rejects_terminal_rewrite(tmp_path, monkeypatch):
    x, _signer, _rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch)
    result = service.submit_settlement(x["job"].job_id)
    assert result.submission_state == CONFIRMED
    with pytest.raises(SettlementAttemptJournalStateError):
        attempts.mark_status_unknown(result.transaction_attempt_id, "should-not-rewrite")


def test_51_status_unknown_reconciliation_uses_local_signature_not_new_submission_id(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    unknown = service.submit_settlement(x["job"].job_id)
    attempt = attempts.get(unknown.transaction_attempt_id)
    captured = []
    def status(sig):
        captured.append(sig)
        return RpcSignatureStatus(False, None, None, None)
    rpc.get_signature_status = status
    service.reconcile_settlement(x["job"].job_id)
    assert captured == [attempt.local_transaction_signature]
    assert captured[0] == unknown.transaction_signature


def test_52_no_new_blockhash_after_submission_has_started(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, _attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    service.submit_settlement(x["job"].job_id)
    blockhash_calls = rpc.calls.count("blockhash")
    rpc.status = RpcSignatureStatus(False, None, None, None)
    service.submit_settlement(x["job"].job_id)
    service.reconcile_settlement(x["job"].job_id)
    assert rpc.calls.count("blockhash") == blockhash_calls == 1
    assert rpc.send_calls == 1


def test_53_restart_reconciliation_rejects_runtime_cluster_mismatch(tmp_path, monkeypatch):
    x, _signer, rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    attempt = attempts.create_or_load_prepared(prepared)
    attempts.begin_submission(attempt.attempt_id)
    recovery = SettlementSubmissionService(
        attempt_journal=attempts, rpc=rpc, expected_genesis_hash=GENESIS_HASH,
        expected_cluster="devnet", expected_program_id=PROGRAM_ID,
        required_commitment="confirmed", simulation_service=None, signing_journal=None,
    )
    with pytest.raises(SettlementSubmissionBindingError, match="attempt_runtime_cluster_mismatch"):
        recovery.reconcile_settlement(x["job"].job_id)
    assert rpc.send_calls == 0


def test_54_restart_reconciliation_rejects_runtime_program_id_mismatch(tmp_path, monkeypatch):
    x, _signer, rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    attempt = attempts.create_or_load_prepared(prepared)
    attempts.begin_submission(attempt.attempt_id)
    wrong_program = str(__import__("solders.pubkey", fromlist=["Pubkey"]).Pubkey.from_bytes(bytes([8]) * 32))
    recovery = SettlementSubmissionService(
        attempt_journal=attempts, rpc=rpc, expected_genesis_hash=GENESIS_HASH,
        expected_cluster="localnet", expected_program_id=wrong_program,
        required_commitment="confirmed", simulation_service=None, signing_journal=None,
    )
    with pytest.raises(SettlementSubmissionBindingError, match="attempt_runtime_program_id_mismatch"):
        recovery.reconcile_settlement(x["job"].job_id)
    assert rpc.send_calls == 0


def test_55_processed_transaction_error_is_pending_until_required_commitment(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(status=RpcSignatureStatus(True, 120, "processed", "Custom(9)"))
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(tmp_path, monkeypatch, rpc=rpc)
    pending = service.submit_settlement(x["job"].job_id)
    assert pending.submission_state == PENDING
    assert pending.confirmation_status == "processed"
    assert pending.transaction_error == "Custom(9)"
    assert pending.failure_category == "transaction_error_awaiting_commitment"
    rpc.status = RpcSignatureStatus(True, 121, "confirmed", "Custom(9)")
    failed = service.reconcile_settlement(x["job"].job_id)
    assert failed.submission_state == FAILED_FINAL
    assert rpc.send_calls == 1


def test_56_two_sqlite_handles_cannot_both_claim_the_same_send(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    x, _signer, _rpc, simulation, request, attempts, _service = _execution(tmp_path, monkeypatch)
    _sim, prepared = _prepared(simulation, request)
    first = attempts.create_or_load_prepared(prepared)
    second_handle = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    barrier = Barrier(2)

    def claim(journal):
        barrier.wait()
        return journal.begin_submission(first.attempt_id)[1]

    with ThreadPoolExecutor(max_workers=2) as pool:
        wins = list(pool.map(claim, (attempts, second_handle)))
    assert sorted(wins) == [False, True]
    assert attempts.get(first.attempt_id).submission_state == SUBMISSION_STARTED
    assert second_handle.get(first.attempt_id).submission_state == SUBMISSION_STARTED
    second_handle.close()


def test_57_restart_after_actual_ambiguous_send_reconciles_before_any_resend(tmp_path, monkeypatch):
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    x, _signer, rpc, _simulation, _request, attempts, service = _execution(
        tmp_path, monkeypatch, rpc=rpc
    )
    unknown = service.submit_settlement(x["job"].job_id)
    assert unknown.submission_state == STATUS_UNKNOWN
    assert rpc.send_calls == 1
    attempts.close()

    reopened = SettlementAttemptJournal(tmp_path / "settlement-attempts.sqlite3")
    rpc.send_mode = "ok"
    rpc.status = RpcSignatureStatus(True, 130, "confirmed", None)
    rpc.calls.clear()
    recovery = _recovery_service(reopened, rpc)
    confirmed = recovery.submit_settlement(x["job"].job_id)
    assert confirmed.submission_state == CONFIRMED
    assert confirmed.slot == 130
    assert rpc.calls == ["genesis", "status"]
    assert rpc.send_calls == 1
