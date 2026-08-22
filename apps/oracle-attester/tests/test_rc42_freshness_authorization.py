"""Deterministic expiry regressions for every off-chain authorization boundary."""
from __future__ import annotations

import pytest
from solders.pubkey import Pubkey

from prophet_sdk.pdas import derive_market_pda
from src.agreed_settlement_signer import AgreedSettlementSigner, CoordinatorSigningBindingError
from src.resolution_coordinator_store import (
    AGREED,
    PENDING,
    CoordinatorRejected,
    ResolutionCoordinatorStore,
    SettlementMessageContext,
    SettlementRuntimeBinding,
    VerifierBinding,
)
from src.resolver_v2_multi_verifier import AgreementPolicy, evaluate_agreement
from src.runtime_config import SolanaRuntimeConfig
from src.settlement_transaction_builder import (
    SettlementTransactionBindingError,
    SettlementTransactionBuilder,
    SettlementTransactionInput,
)
from src.signing_journal import SigningJournal
from src.vault_transit_threshold_signer import ThresholdResolutionSigner
from tests.test_agreed_settlement_signing_integration import H, _canonical_inputs, _context, _verification
from tests.test_resolver_v2_multi_verifier import POLICY, result
from tests.test_settlement_transaction_construction import (
    BLOCKHASH_1,
    FEE_PAYER_1,
    GENESIS_HASH,
    OPEN_TS,
    PROGRAM_ID,
)
from tests.test_signing_journal import _fixture as signing_fixture


class _Clock:
    def __init__(self, now: int = 100):
        self.now = now

    def __call__(self) -> int:
        return self.now


def _results(*, valid_until: str = "1000"):
    definition, evidence = _canonical_inputs()
    return definition, evidence, _verification(definition, evidence, slot="A"), _verification(definition, evidence, slot="B")


def _agreed_state(tmp_path, clock: _Clock):
    definition, evidence, a, b = _results()
    market, _ = derive_market_pda(
        Pubkey.default(), bytes.fromhex(a["definition_hash"]), OPEN_TS, 0, Pubkey.from_string(PROGRAM_ID)
    )
    store = ResolutionCoordinatorStore(
        tmp_path / "coordinator.sqlite",
        verifier_a=VerifierBinding("A", a["verifier"]),
        verifier_b=VerifierBinding("B", b["verifier"]),
        clock_ms=clock,
    )
    job = store.register_job(market=bytes(market).hex(), resolver_definition=definition, evidence=evidence)
    store.bind_settlement_context(job.job_id, _context(program_id=PROGRAM_ID, notary_config=PROGRAM_ID))
    store.bind_settlement_runtime(
        job.job_id,
        SettlementRuntimeBinding(cluster="localnet", genesis_hash=GENESIS_HASH, program_id=PROGRAM_ID),
    )
    assert store.record_result(job_id=job.job_id, slot="A", result=a).state != AGREED
    assert store.record_result(job_id=job.job_id, slot="B", result=b).state == AGREED
    return store, job, a, b


def test_verifier_a_and_b_reject_old_evidence_with_injected_current_time():
    from tests.test_dual_verifier_runtime_independence import (
        _CountingIndependentChecker,
        _CountingIndependentFactory,
        _CountingPrimaryFactory,
        _config,
        _descriptor,
    )
    from tests.test_resolver_v2_adapters import _zktls_evidence, _trust
    from src.resolver_verifier_runtime import ResolverVerifierRuntime
    from src.runtime_adapter_factory import RuntimeAdapterRegistry

    definition, _, evidence = _zktls_evidence()
    a_descriptor, b_descriptor = _descriptor("prophet.verifier.runtime.a", 70), _descriptor("prophet.verifier.runtime.b", 71)
    registry = RuntimeAdapterRegistry()
    a = ResolverVerifierRuntime(_config(a_descriptor["adapter_id"]), _CountingPrimaryFactory(runtime_config=_config(a_descriptor["adapter_id"]), verifier_descriptors={"zktls": a_descriptor}, registry=registry, clock_ms=lambda: 1000), a_descriptor)
    b = ResolverVerifierRuntime(_config(b_descriptor["adapter_id"]), _CountingIndependentFactory(runtime_config=_config(b_descriptor["adapter_id"]), verifier_descriptor=b_descriptor, checker=_CountingIndependentChecker(), registry=registry, clock_ms=lambda: 1000), b_descriptor)
    assert a.verify(resolver_definition=definition, evidence=evidence, trust_model=_trust())["result"] == "REJECTED"
    assert b.verify(resolver_definition=definition, evidence=evidence, trust_model=_trust())["result"] == "REJECTED"


def test_agreement_rejects_any_expired_result():
    assert evaluate_agreement([result("verifier-a"), result("verifier-b")], POLICY, now_ms=150).allowed
    assert not evaluate_agreement([result("verifier-a"), result("verifier-b", valid_until="149")], POLICY, now_ms=150).allowed
    assert not evaluate_agreement([result("verifier-a", valid_until="149"), result("verifier-b", valid_until="149")], POLICY, now_ms=150).allowed


def test_coordinator_rejects_expired_result_before_any_agreement(tmp_path):
    clock = _Clock(1001)
    definition, evidence, a, b = _results()
    store = ResolutionCoordinatorStore(tmp_path / "coordinator.sqlite", verifier_a=VerifierBinding("A", a["verifier"]), verifier_b=VerifierBinding("B", b["verifier"]), clock_ms=clock)
    job = store.register_job(market=H(1), resolver_definition=definition, evidence=evidence)
    with pytest.raises(CoordinatorRejected, match="verification_result_expired"):
        store.record_result(job_id=job.job_id, slot="A", result=a)
    persisted = store.get_job(job.job_id)
    assert persisted.state == PENDING and persisted.verifier_a_result is None and persisted.verifier_b_result is None


def test_expired_agreed_job_causes_zero_vault_calls_and_restart_stays_blocked(tmp_path, monkeypatch):
    clock = _Clock()
    store, job, a, b = _agreed_state(tmp_path, clock)
    threshold, journal, signer_a, signer_b, transport = signing_fixture(tmp_path, monkeypatch)
    service = AgreedSettlementSigner(coordinator_state=store, signing_journal=journal, threshold_signer=threshold, clock_ms=clock)
    clock.now = 1001
    with pytest.raises(CoordinatorSigningBindingError):
        service.sign_agreed_job(job.job_id)
    assert transport.calls == []

    store.close()
    journal.close()
    reopened_store = ResolutionCoordinatorStore(tmp_path / "coordinator.sqlite", verifier_a=VerifierBinding("A", a["verifier"]), verifier_b=VerifierBinding("B", b["verifier"]), clock_ms=clock)
    reopened_journal = SigningJournal(tmp_path / "journal.sqlite")
    reopened_threshold = ThresholdResolutionSigner(signer_a=signer_a, signer_b=signer_b, journal=reopened_journal)
    reopened = AgreedSettlementSigner(coordinator_state=reopened_store, signing_journal=reopened_journal, threshold_signer=reopened_threshold, clock_ms=clock)
    with pytest.raises(CoordinatorSigningBindingError):
        reopened.sign_agreed_job(job.job_id)
    assert transport.calls == []


def test_expired_authorization_cannot_build_transaction_artifact(tmp_path, monkeypatch):
    clock = _Clock()
    store, job, _, _ = _agreed_state(tmp_path, clock)
    threshold, journal, _, _, _ = signing_fixture(tmp_path, monkeypatch)
    signed = AgreedSettlementSigner(coordinator_state=store, signing_journal=journal, threshold_signer=threshold, clock_ms=clock).sign_agreed_job(job.job_id)
    clock.now = 1001
    builder = SettlementTransactionBuilder(
        coordinator_state=store,
        signing_journal=journal,
        threshold_signer=threshold,
        solana_runtime=SolanaRuntimeConfig("localnet", GENESIS_HASH, PROGRAM_ID),
        clock_ms=clock,
    )
    request = SettlementTransactionInput(job.job_id, signed.signing_intent_id, FEE_PAYER_1, BLOCKHASH_1)
    with pytest.raises(SettlementTransactionBindingError):
        builder.build(request)
