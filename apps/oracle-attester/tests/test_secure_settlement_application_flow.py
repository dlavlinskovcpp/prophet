from types import SimpleNamespace

import pytest
from solders.keypair import Keypair

from prophet_sdk.pdas import derive_market_pda

from src.agreed_settlement_signer import (
    AgreedSettlementSigner,
    CoordinatorJobNotAgreed,
    canonical_message_for_agreed_job,
)
from src.resolution_coordinator import ResolutionCoordinator
from src.resolution_coordinator_store import (
    AGREED,
    A_RECORDED,
    CONFLICT,
    ResolutionCoordinatorStore,
    SettlementRuntimeBinding,
    VerifierBinding,
)
from src.runtime_config import (
    SettlementExecutionRuntimeConfig,
    SettlementFeePayerConfig,
    SettlementRpcConfig,
    SolanaRuntimeConfig,
)
from src.secure_settlement_service import SecureSettlementEngine
from src.settlement_simulation import SettlementSimulationService
from src.settlement_submission import SettlementSubmissionService
from src.settlement_rpc import RpcSignatureStatus
from src.settlement_submission_journal import (
    CONFIRMED,
    STATUS_UNKNOWN,
    SettlementAttemptJournal,
)
from src.settlement_transaction_builder import SettlementTransactionBuilder
from src.signing_journal import SigningJournal
from src.vault_transit_threshold_signer import ThresholdResolutionSigner
from tests.test_agreed_settlement_signing_integration import (
    _canonical_inputs,
    _context,
    _verification,
)
from tests.test_settlement_simulation import CountingFeePayerSigner
from tests.test_settlement_submission import FakeSubmissionRpc
from tests.test_settlement_transaction_construction import (
    GENESIS_HASH,
    OPEN_TS,
    PROGRAM_ID,
)
from tests.test_signing_journal import _fixture as signing_fixture


class CountingVerifierClient:
    def __init__(self, slot, result):
        self.slot = slot
        self.result = result
        self.calls = 0
        verifier = result["verifier"]
        self.config = SimpleNamespace(
            expected_verifier_id=verifier["adapter_id"],
            expected_verifier_version=verifier["adapter_version"],
            expected_verifier_implementation_digest=verifier["implementation_digest"],
        )

    def verify(self, **_request):
        self.calls += 1
        return self.result


class LegacyGenericSignerTripwire:
    def __init__(self):
        self.calls = 0

    def sign(self, *_args, **_kwargs):
        self.calls += 1
        raise AssertionError("legacy generic signer must never participate")


def _pipeline(tmp_path, monkeypatch, *, conflict=False):
    definition, evidence = _canonical_inputs()
    a_result = _verification(definition, evidence, slot="A")
    b_result = _verification(
        definition, evidence, slot="B", outcome="NO" if conflict else "INVALID"
    )
    a = CountingVerifierClient("A", a_result)
    b = CountingVerifierClient("B", b_result)
    store = ResolutionCoordinatorStore(
        tmp_path / "coordinator.sqlite",
        verifier_a=VerifierBinding("A", a_result["verifier"]),
        verifier_b=VerifierBinding("B", b_result["verifier"]),
    )
    resolver_hash = bytes.fromhex(a_result["definition_hash"])
    market, _ = derive_market_pda(
        resolver_hash, OPEN_TS, __import__("solders.pubkey", fromlist=["Pubkey"]).Pubkey.from_string(PROGRAM_ID)
    )
    coordinator = ResolutionCoordinator(
        state=store, verifier_client_a=a, verifier_client_b=b
    )
    runtime = SolanaRuntimeConfig("localnet", GENESIS_HASH, PROGRAM_ID)
    job = coordinator.resolve(
        market=bytes(market).hex(),
        resolver_definition=definition,
        evidence=evidence,
        trust_model=definition["trust_model"],
        settlement_context=_context(),
        settlement_runtime=SettlementRuntimeBinding(
            cluster=runtime.cluster,
            genesis_hash=runtime.genesis_hash,
            program_id=runtime.prophet_program_id,
        ),
    )

    threshold, journal, signer_a, signer_b, vault = signing_fixture(tmp_path, monkeypatch)
    agreed = AgreedSettlementSigner(
        coordinator_state=store,
        signing_journal=journal,
        threshold_signer=threshold,
    )
    builder = SettlementTransactionBuilder(
        coordinator_state=store,
        signing_journal=journal,
        threshold_signer=threshold,
        solana_runtime=runtime,
    )
    rpc = FakeSubmissionRpc()
    execution = SettlementExecutionRuntimeConfig(
        rpc_url_env="UNUSED",
        expected_cluster=runtime.cluster,
        expected_genesis_hash=runtime.genesis_hash,
        fee_payer=SettlementFeePayerConfig("UNUSED"),
        rpc=SettlementRpcConfig(10, "confirmed"),
    )
    simulation = SettlementSimulationService(
        builder=builder,
        solana_runtime=runtime,
        execution_config=execution,
        fee_payer_signer=CountingFeePayerSigner(Keypair.from_seed(bytes([41]) * 32)),
        rpc=rpc,
        environment="localtest",
        mode="test",
    )
    submission = SettlementSubmissionService(
        attempt_journal=SettlementAttemptJournal(tmp_path / "submission.sqlite"),
        rpc=rpc,
        expected_genesis_hash=runtime.genesis_hash,
        expected_cluster=runtime.cluster,
        expected_program_id=runtime.prophet_program_id,
        required_commitment="confirmed",
        simulation_service=simulation,
        signing_journal=journal,
    )
    legacy = LegacyGenericSignerTripwire()
    return (
        SecureSettlementEngine(agreed_signer=agreed, submission_service=submission),
        store,
        job,
        a,
        b,
        journal,
        vault,
        rpc,
        legacy,
    )


def test_full_secure_agreed_path_is_durable_strict_2of2_and_submitted(tmp_path, monkeypatch):
    engine, store, job, a, b, journal, vault, rpc, legacy = _pipeline(
        tmp_path, monkeypatch
    )
    assert job.state == AGREED

    result = engine.settle(job.job_id)

    assert result.submission_state == CONFIRMED
    assert a.calls == 1 and b.calls == 1
    assert store.get_job(job.job_id).state == AGREED
    assert journal._db.execute("SELECT COUNT(*) FROM signing_intents").fetchone()[0] == 1
    assert [call[0] for call in vault.calls] == ["key-a", "key-b"]
    assert rpc.calls == ["genesis", "blockhash", "simulate", "send", "status"]
    assert legacy.calls == 0


def test_partial_job_rejected_before_signing_intent_or_vault(tmp_path, monkeypatch):
    definition, evidence = _canonical_inputs()
    a_result = _verification(definition, evidence, slot="A")
    b_result = _verification(definition, evidence, slot="B")
    store = ResolutionCoordinatorStore(
        tmp_path / "partial-coordinator.sqlite",
        verifier_a=VerifierBinding("A", a_result["verifier"]),
        verifier_b=VerifierBinding("B", b_result["verifier"]),
    )
    resolver_hash = bytes.fromhex(a_result["definition_hash"])
    market, _ = derive_market_pda(
        resolver_hash,
        OPEN_TS,
        __import__("solders.pubkey", fromlist=["Pubkey"]).Pubkey.from_string(PROGRAM_ID),
    )
    job = store.register_job(
        market=bytes(market).hex(), resolver_definition=definition, evidence=evidence
    )
    store.bind_settlement_context(job.job_id, _context())
    store.bind_settlement_runtime(
        job.job_id, SettlementRuntimeBinding("localnet", GENESIS_HASH, PROGRAM_ID)
    )
    partial = store.record_result(job_id=job.job_id, slot="A", result=a_result)
    assert partial.state == A_RECORDED

    threshold, journal, _signer_a, _signer_b, vault = signing_fixture(
        tmp_path, monkeypatch
    )
    agreed = AgreedSettlementSigner(
        coordinator_state=store, signing_journal=journal, threshold_signer=threshold
    )
    with pytest.raises(CoordinatorJobNotAgreed):
        agreed.sign_agreed_job(job.job_id)
    assert journal._db.execute("SELECT COUNT(*) FROM signing_intents").fetchone()[0] == 0
    assert vault.calls == []


def test_real_sqlite_restart_resumes_secure_path_without_legacy_fallback(
    tmp_path, monkeypatch
):
    definition, evidence = _canonical_inputs()
    a_result = _verification(definition, evidence, slot="A")
    b_result = _verification(definition, evidence, slot="B")
    verifier_a = VerifierBinding("A", a_result["verifier"])
    verifier_b = VerifierBinding("B", b_result["verifier"])
    coordinator_path = tmp_path / "restart-coordinator.sqlite"
    store = ResolutionCoordinatorStore(
        coordinator_path, verifier_a=verifier_a, verifier_b=verifier_b
    )
    resolver_hash = bytes.fromhex(a_result["definition_hash"])
    market, _ = derive_market_pda(
        resolver_hash,
        OPEN_TS,
        __import__("solders.pubkey", fromlist=["Pubkey"]).Pubkey.from_string(PROGRAM_ID),
    )
    runtime = SolanaRuntimeConfig("localnet", GENESIS_HASH, PROGRAM_ID)
    job = store.register_job(
        market=bytes(market).hex(), resolver_definition=definition, evidence=evidence
    )
    store.bind_settlement_context(job.job_id, _context())
    store.bind_settlement_runtime(
        job.job_id,
        SettlementRuntimeBinding(
            runtime.cluster, runtime.genesis_hash, runtime.prophet_program_id
        ),
    )
    assert store.record_result(job_id=job.job_id, slot="A", result=a_result).state == A_RECORDED
    store.close()

    store = ResolutionCoordinatorStore(
        coordinator_path, verifier_a=verifier_a, verifier_b=verifier_b
    )
    recovered_partial = store.get_job(job.job_id)
    assert recovered_partial.state == A_RECORDED
    assert recovered_partial.verifier_b_result is None
    assert store.record_result(job_id=job.job_id, slot="B", result=b_result).state == AGREED
    store.close()

    store = ResolutionCoordinatorStore(
        coordinator_path, verifier_a=verifier_a, verifier_b=verifier_b
    )
    recovered_agreed = store.get_job(job.job_id)
    assert recovered_agreed.state == AGREED

    threshold, journal, signer_a, signer_b, vault = signing_fixture(
        tmp_path, monkeypatch
    )
    message = canonical_message_for_agreed_job(store, recovered_agreed)
    intent = threshold.prepare_2_of_2(
        message, coordinator_job_id=recovered_agreed.job_id
    )
    pinned_a = signer_a.for_pinned_epoch(
        signer_id=intent.signer_a.signer_id,
        public_key=intent.signer_a.public_key,
        key_version=intent.signer_a.key_version,
    )
    assert journal.begin_signer(intent.signing_scope_id, "A") is None
    journal.record_signature(
        intent.signing_scope_id, "A", pinned_a.sign_canonical_message(message)
    )
    assert [call[0] for call in vault.calls] == ["key-a"]
    journal.close()

    journal = SigningJournal(tmp_path / "journal.sqlite")
    threshold = ThresholdResolutionSigner(
        signer_a=signer_a, signer_b=signer_b, journal=journal
    )
    threshold.resume_2_of_2(message)
    assert [call[0] for call in vault.calls] == ["key-a", "key-b"]
    agreed = AgreedSettlementSigner(
        coordinator_state=store, signing_journal=journal, threshold_signer=threshold
    )

    builder = SettlementTransactionBuilder(
        coordinator_state=store,
        signing_journal=journal,
        threshold_signer=threshold,
        solana_runtime=runtime,
    )
    rpc = FakeSubmissionRpc(send_mode="fail_after_receive")
    execution = SettlementExecutionRuntimeConfig(
        rpc_url_env="UNUSED",
        expected_cluster=runtime.cluster,
        expected_genesis_hash=runtime.genesis_hash,
        fee_payer=SettlementFeePayerConfig("UNUSED"),
        rpc=SettlementRpcConfig(10, "confirmed"),
    )
    simulation = SettlementSimulationService(
        builder=builder,
        solana_runtime=runtime,
        execution_config=execution,
        fee_payer_signer=CountingFeePayerSigner(Keypair.from_seed(bytes([41]) * 32)),
        rpc=rpc,
        environment="localtest",
        mode="test",
    )
    submission_path = tmp_path / "restart-submission.sqlite"
    attempts = SettlementAttemptJournal(submission_path)
    submission = SettlementSubmissionService(
        attempt_journal=attempts,
        rpc=rpc,
        expected_genesis_hash=runtime.genesis_hash,
        expected_cluster=runtime.cluster,
        expected_program_id=runtime.prophet_program_id,
        required_commitment="confirmed",
        simulation_service=simulation,
        signing_journal=journal,
    )
    legacy = LegacyGenericSignerTripwire()
    first = SecureSettlementEngine(
        agreed_signer=agreed, submission_service=submission
    ).settle(job.job_id)
    assert first.submission_state == STATUS_UNKNOWN
    assert rpc.send_calls == 1
    assert [call[0] for call in vault.calls] == ["key-a", "key-b"]
    attempts.close()

    attempts = SettlementAttemptJournal(submission_path)
    rpc.send_mode = "ok"
    rpc.status = RpcSignatureStatus(True, 88, "confirmed", None)
    submission = SettlementSubmissionService(
        attempt_journal=attempts,
        rpc=rpc,
        expected_genesis_hash=runtime.genesis_hash,
        expected_cluster=runtime.cluster,
        expected_program_id=runtime.prophet_program_id,
        required_commitment="confirmed",
        simulation_service=simulation,
        signing_journal=journal,
    )
    second = SecureSettlementEngine(
        agreed_signer=agreed, submission_service=submission
    ).settle(job.job_id)
    assert second.submission_state == CONFIRMED
    assert second.slot == 88
    assert rpc.send_calls == 1
    assert legacy.calls == 0
    assert [call[0] for call in vault.calls] == ["key-a", "key-b"]


def test_conflict_stops_before_journal_vault_construction_simulation_or_submission(
    tmp_path, monkeypatch
):
    engine, store, job, a, b, journal, vault, rpc, legacy = _pipeline(
        tmp_path, monkeypatch, conflict=True
    )
    assert job.state == CONFLICT
    with pytest.raises(CoordinatorJobNotAgreed):
        engine.settle(job.job_id)

    assert a.calls == 1 and b.calls == 1
    assert store.get_job(job.job_id).state == CONFLICT
    assert journal._db.execute("SELECT COUNT(*) FROM signing_intents").fetchone()[0] == 0
    assert vault.calls == []
    assert rpc.calls == []
    assert legacy.calls == 0
