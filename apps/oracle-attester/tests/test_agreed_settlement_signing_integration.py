import hashlib
import inspect
import sqlite3
from dataclasses import replace

import pytest
from solders.pubkey import Pubkey

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from src.resolver_v2_pipeline import resolver_v2

from src.agreed_settlement_signer import (
    AgreedSettlementSigner,
    CoordinatorJobMissing,
    CoordinatorJobNotAgreed,
    CoordinatorSigningBindingError,
    CoordinatorSigningConflict,
    SigningRecoveryRequired,
)
from src.resolution_coordinator_store import (
    AGREED,
    CONFLICT,
    CoordinatorRejected,
    ResolutionCoordinatorStore,
    SettlementMessageContext,
    VerifierBinding,
)
from src.resolver_v2_pipeline import build_legacy_settlement_message
from src.signing_journal import BOTH_SIGNED, SigningJournal
from src.vault_transit_threshold_signer import ThresholdResolutionSigner
from tests.test_signing_journal import _bindings, _fixture as signing_fixture
from tests.test_signer_key_rotation import _fixture as rotation_fixture

H = lambda value: f"{value:02x}" * 32
GOLDEN_AGREED_RESOLVE_V2_HEX = (
    "50524f504845545f5245534f4c56455f5632"
    + "00" * 96
    + "338072381a534345857ab40d80da0f8c7a36547afc2d672e21bc7d7290f7b8dc"
    + "f9ffffffffffffff2a00000000000000090000000000000003"
    + "05" * 32
    + "06" * 32
)


def _adapter(adapter_id, byte):
    return {
        "schema": resolver_v2.SCHEMAS["adapter"],
        "schema_version": resolver_v2.VERSION,
        "adapter_id": adapter_id,
        "adapter_version": "2.0.0",
        "implementation_digest": H(byte),
    }


def _canonical_inputs():
    trust = {
        "schema": resolver_v2.SCHEMAS["trust_model"],
        "schema_version": resolver_v2.VERSION,
        "trust_model_id": "dual-verifier",
        "trust_model_version": "2.0.0",
        "document_hash": H(9),
    }
    definition = {
        "schema": resolver_v2.SCHEMAS["definition"],
        "schema_version": resolver_v2.VERSION,
        "resolver_id": "test-resolver",
        "resolver_type": "zktls",
        "adapter": _adapter("source-adapter", 3),
        "trust_model": trust,
        "source": {}, "verification_policy": {}, "evaluation": {},
        "timing": {"not_before_ms": "0", "observation_deadline_ms": "1000", "max_evidence_age_ms": "1000"},
        "conflict_policy": {}, "fallback_policy": {},
    }
    resolver_v2.validate_resolver_definition(definition)
    definition_hash = resolver_v2.resolver_definition_hash(definition).hex()
    payload = b"proof"
    evidence = {
        "schema": resolver_v2.SCHEMAS["evidence"],
        "schema_version": resolver_v2.VERSION,
        "evidence_id": H(7),
        "definition_hash": definition_hash,
        "acquisition_id": "acq-1",
        "acquired_at_ms": "10", "source_time_ms": "10", "source_sequence": None,
        "source_locator": {}, "source_commitment": H(8),
        "payload_hex": payload.hex(), "payload_hash": hashlib.sha256(payload).hexdigest(),
        "provenance": {}, "transport": {}, "collector": {}, "previous_evidence_hash": None,
    }
    resolver_v2.validate_evidence_envelope(evidence)
    return definition, evidence


def _verification(definition, evidence, *, slot, outcome="INVALID"):
    facts = resolver_v2.canonical_json_bytes({"outcome": outcome, "status": "VERIFIED"})
    result = {
        "schema": resolver_v2.SCHEMAS["verification"],
        "schema_version": resolver_v2.VERSION,
        "definition_hash": resolver_v2.resolver_definition_hash(definition).hex(),
        "evidence_hash": resolver_v2.evidence_hash(evidence).hex(),
        "verifier": _adapter(f"verifier-{slot.lower()}", 10 if slot == "A" else 11),
        "result": "VERIFIED", "checks": [],
        "verified_facts_hex": facts.hex(), "verified_facts_hash": hashlib.sha256(facts).hexdigest(),
        "observed_at_ms": "10", "valid_from_ms": "0", "valid_until_ms": "1000", "finality": None,
    }
    resolver_v2.validate_verification_result(result)
    return result


def _context(**changes):
    values = dict(
        program_id="11111111111111111111111111111111",
        notary_config="11111111111111111111111111111111",
        open_ts=-7,
        resolve_ts=42,
        notary_config_version=9,
        proof_hash=H(5),
        public_inputs_hash=H(6),
    )
    values.update(changes)
    return SettlementMessageContext(**values)


def _state(path, *, market=H(0), terminal="AGREED", bind_context=True):
    definition, evidence = _canonical_inputs()
    a = _verification(definition, evidence, slot="A")
    b = _verification(definition, evidence, slot="B", outcome="NO" if terminal == "CONFLICT" else "INVALID")
    store = ResolutionCoordinatorStore(path, verifier_a=VerifierBinding("A", a["verifier"]), verifier_b=VerifierBinding("B", b["verifier"]))
    job = store.register_job(market=market, resolver_definition=definition, evidence=evidence)
    if bind_context:
        store.bind_settlement_context(job.job_id, _context())
    if terminal in ("PARTIAL", "AGREED", "CONFLICT"):
        job = store.record_result(job_id=job.job_id, slot="A", result=a)
    if terminal in ("AGREED", "CONFLICT"):
        job = store.record_result(job_id=job.job_id, slot="B", result=b)
    return store, store.get_job(job.job_id), definition, evidence, a, b


def _service(tmp_path, monkeypatch, *, terminal="AGREED", bind_context=True, market=H(0)):
    store, job, *_ = _state(tmp_path / "coordinator.sqlite", market=market, terminal=terminal, bind_context=bind_context)
    threshold, journal, signer_a, signer_b, transport = signing_fixture(tmp_path, monkeypatch)
    service = AgreedSettlementSigner(coordinator_state=store, signing_journal=journal, threshold_signer=threshold)
    return service, store, job, threshold, journal, signer_a, signer_b, transport


def test_agreed_job_creates_one_linked_intent_and_completes_strict_2of2(tmp_path, monkeypatch):
    service, _, job, _, journal, _, _, transport = _service(tmp_path, monkeypatch)
    result = service.sign_agreed_job(job.job_id)
    assert result.signing_state == BOTH_SIGNED
    assert journal.get_coordinator_link(job.job_id).signing_scope_id == result.signing_intent_id
    assert [call[0] for call in transport.calls] == ["key-a", "key-b"]


def test_conflict_job_is_permanently_non_signable_with_zero_vault_calls(tmp_path, monkeypatch):
    service, _, job, _, journal, _, _, transport = _service(tmp_path, monkeypatch, terminal="CONFLICT")
    assert job.state == CONFLICT
    with pytest.raises(CoordinatorJobNotAgreed): service.sign_agreed_job(job.job_id)
    assert transport.calls == []
    assert journal._db.execute("SELECT COUNT(*) FROM signing_intents").fetchone()[0] == 0
    with pytest.raises(Exception, match="coordinator_signing_link_not_found"): journal.get_coordinator_link(job.job_id)


def test_partial_job_is_non_signable_with_zero_vault_calls(tmp_path, monkeypatch):
    service, _, job, _, journal, _, _, transport = _service(tmp_path, monkeypatch, terminal="PARTIAL")
    with pytest.raises(CoordinatorJobNotAgreed): service.sign_agreed_job(job.job_id)
    assert transport.calls == []
    assert journal._db.execute("SELECT COUNT(*) FROM signing_intents").fetchone()[0] == 0
    with pytest.raises(Exception, match="coordinator_signing_link_not_found"): journal.get_coordinator_link(job.job_id)


def test_unknown_job_rejects_before_signing(tmp_path, monkeypatch):
    service, *_rest, transport = _service(tmp_path, monkeypatch)
    with pytest.raises(CoordinatorJobMissing): service.sign_agreed_job(H(99))
    assert transport.calls == []




def test_malformed_historical_agreed_record_rejects_before_vault(tmp_path, monkeypatch):
    service, store, job, _, journal, _, _, transport = _service(tmp_path, monkeypatch)
    store._db.execute(
        "UPDATE resolution_jobs SET verifier_a_json = ? WHERE job_id = ?",
        ("{}", job.job_id),
    )
    with pytest.raises(CoordinatorSigningBindingError, match="agreed_(historical_record_malformed|verifier_identity_mismatch)"):
        service.sign_agreed_job(job.job_id)
    assert transport.calls == []
    assert journal._db.execute("SELECT COUNT(*) FROM signing_intents").fetchone()[0] == 0

def test_missing_durable_settlement_context_fails_closed_before_vault(tmp_path, monkeypatch):
    service, _, job, _, _, _, _, transport = _service(tmp_path, monkeypatch, bind_context=False)
    with pytest.raises(CoordinatorSigningBindingError, match="durable_settlement_context_missing"):
        service.sign_agreed_job(job.job_id)
    assert transport.calls == []


def test_settlement_context_is_immutable_and_cannot_be_bound_after_verifier_progress(tmp_path):
    store, job, *_ = _state(tmp_path / "bound.sqlite", terminal="PENDING")
    assert store.bind_settlement_context(job.job_id, _context()) == _context()
    with pytest.raises(CoordinatorRejected, match="settlement_context_immutable"):
        store.bind_settlement_context(job.job_id, _context(proof_hash=H(12)))
    store.close()
    store, job, *_ = _state(tmp_path / "late.sqlite", terminal="PARTIAL", bind_context=False)
    with pytest.raises(CoordinatorRejected, match="settlement_context_binding_too_late"):
        store.bind_settlement_context(job.job_id, _context())


def test_repeated_same_agreed_job_reuses_same_intent_and_completed_bundle_zero_calls(tmp_path, monkeypatch):
    service, _, job, _, journal, _, _, transport = _service(tmp_path, monkeypatch)
    first = service.sign_agreed_job(job.job_id)
    durable_before = journal.get(first.signing_intent_id)
    before = len(transport.calls)
    second = service.sign_agreed_job(job.job_id)
    assert second == first and second.signing_intent_id == first.signing_intent_id
    assert journal.get(first.signing_intent_id) == durable_before
    assert len(transport.calls) == before == 2


def test_a_durable_b_missing_restart_reuses_a_and_calls_only_b(tmp_path, monkeypatch):
    service, store, job, threshold, journal, a, b, transport = _service(tmp_path, monkeypatch)
    message = service._canonical_message(job)
    intent = threshold.prepare_2_of_2(message, coordinator_job_id=job.job_id)
    journal.begin_signer(intent.signing_scope_id, "A")
    journal.record_signature(intent.signing_scope_id, "A", a.sign_canonical_message(message))
    assert [call[0] for call in transport.calls] == ["key-a"]
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = AgreedSettlementSigner(coordinator_state=store, signing_journal=reopened, threshold_signer=ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened))
    result = recovered.sign_agreed_job(job.job_id)
    assert result.signing_state == BOTH_SIGNED
    assert [call[0] for call in transport.calls] == ["key-a", "key-b"]


def test_uncertain_signer_state_preserves_existing_fail_closed_recovery(tmp_path, monkeypatch):
    service, _, job, threshold, journal, _, _, transport = _service(tmp_path, monkeypatch)
    message = service._canonical_message(job)
    intent = threshold.prepare_2_of_2(message, coordinator_job_id=job.job_id)
    journal.begin_signer(intent.signing_scope_id, "A")
    with pytest.raises(SigningRecoveryRequired): service.sign_agreed_job(job.job_id)
    assert transport.calls == []
    assert journal.get_coordinator_link(job.job_id).signing_scope_id == intent.signing_scope_id


def test_restart_after_intent_reuses_same_intent(tmp_path, monkeypatch):
    service, store, job, threshold, journal, a, b, transport = _service(tmp_path, monkeypatch)
    message = service._canonical_message(job)
    intent = threshold.prepare_2_of_2(message, coordinator_job_id=job.job_id)
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = AgreedSettlementSigner(coordinator_state=store, signing_journal=reopened, threshold_signer=ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened))
    result = recovered.sign_agreed_job(job.job_id)
    assert result.signing_intent_id == intent.signing_scope_id
    assert [call[0] for call in transport.calls] == ["key-a", "key-b"]


def test_restart_after_complete_returns_same_bundle_with_zero_vault_calls(tmp_path, monkeypatch):
    service, store, job, _, journal, a, b, transport = _service(tmp_path, monkeypatch)
    first = service.sign_agreed_job(job.job_id)
    assert len(transport.calls) == 2
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = AgreedSettlementSigner(coordinator_state=store, signing_journal=reopened, threshold_signer=ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened))
    second = recovered.sign_agreed_job(job.job_id)
    assert second.signature_bundle == first.signature_bundle
    assert len(transport.calls) == 2


def test_rotation_after_intent_keeps_pinned_a1_b1(tmp_path, monkeypatch):
    store, job, *_ = _state(tmp_path / "coordinator.sqlite")
    _, threshold, journal, a, b, transport, _ = rotation_fixture(tmp_path, monkeypatch)
    service = AgreedSettlementSigner(coordinator_state=store, signing_journal=journal, threshold_signer=threshold)
    message = service._canonical_message(job)
    intent = threshold.prepare_2_of_2(message, coordinator_job_id=job.job_id, intent_created_at_ms=50)
    assert (intent.signer_a.key_version, intent.signer_b.key_version) == (1, 1)
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = AgreedSettlementSigner(coordinator_state=store, signing_journal=reopened, threshold_signer=ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened))
    result = recovered.sign_agreed_job(job.job_id)
    assert (result.signer_a_key_version, result.signer_b_key_version) == (1, 1)
    assert [(key, version) for key, _, version in transport.calls] == [("key-a", 1), ("key-b", 1)]


def test_new_unrelated_agreed_job_after_rotation_selects_new_epochs(tmp_path, monkeypatch):
    store1, job1, *_ = _state(tmp_path / "c1.sqlite", market=H(0))
    _, threshold, journal, a, b, _, _ = rotation_fixture(tmp_path, monkeypatch)
    service1 = AgreedSettlementSigner(coordinator_state=store1, signing_journal=journal, threshold_signer=threshold)
    threshold.prepare_2_of_2(service1._canonical_message(job1), coordinator_job_id=job1.job_id, intent_created_at_ms=50)
    store2, job2, *_ = _state(tmp_path / "c2.sqlite", market=H(1))
    service2 = AgreedSettlementSigner(coordinator_state=store2, signing_journal=journal, threshold_signer=threshold)
    result = service2.sign_agreed_job(job2.job_id)
    assert (result.signer_a_key_version, result.signer_b_key_version) == (2, 2)


def test_public_signing_boundary_accepts_only_job_id_and_caller_cannot_override_result_fields(tmp_path, monkeypatch):
    service, _, job, _, _, _, _, transport = _service(tmp_path, monkeypatch)
    assert list(inspect.signature(service.sign_agreed_job).parameters) == ["job_id"]
    for field, value in (("outcome", "YES"), ("resolver_id", "evil"), ("market", H(9)), ("canonical_digest", H(8))):
        with pytest.raises(TypeError): service.sign_agreed_job(job.job_id, **{field: value})
    assert transport.calls == []


def test_conflicting_digest_for_same_protocol_scope_rejects_before_vault(tmp_path, monkeypatch):
    service, _, job, _, journal, a, b, transport = _service(tmp_path, monkeypatch)
    message = service._canonical_message(job)
    conflicting = bytearray(message); conflicting[170] = 1  # outcome byte is outside scope, inside digest
    journal.reserve_intent(bytes(conflicting), signer_a=_bindings(a, b)[0], signer_b=_bindings(a, b)[1])
    with pytest.raises(CoordinatorSigningConflict): service.sign_agreed_job(job.job_id)
    assert transport.calls == []


def test_agreed_path_bytes_match_frozen_existing_resolve_v2_layout(tmp_path, monkeypatch):
    service, _, job, _, _, _, _, _ = _service(tmp_path, monkeypatch)
    message = service._canonical_message(job)
    assert len(message) == 235 and message.hex() == GOLDEN_AGREED_RESOLVE_V2_HEX
    direct = build_legacy_settlement_message(
        program_id="11111111111111111111111111111111", market="11111111111111111111111111111111",
        notary_config="11111111111111111111111111111111", resolver_hash=job.resolver_definition_hash,
        open_ts=-7, resolve_ts=42, notary_config_version=9, outcome="INVALID", proof_hash=H(5), public_inputs_hash=H(6),
    )
    assert message == direct


def test_agreed_path_binds_exact_notary_snapshot_address_and_version_without_wire_change():
    config_v1 = str(Pubkey.from_bytes(bytes([41]) * 32))
    config_v2 = str(Pubkey.from_bytes(bytes([42]) * 32))
    common = dict(
        program_id="11111111111111111111111111111111",
        market="11111111111111111111111111111111",
        resolver_hash=H(4),
        open_ts=-7,
        resolve_ts=42,
        outcome="INVALID",
        proof_hash=H(5),
        public_inputs_hash=H(6),
    )
    pinned_v1 = build_legacy_settlement_message(
        **common, notary_config=config_v1, notary_config_version=1
    )
    different_snapshot_address = build_legacy_settlement_message(
        **common, notary_config=config_v2, notary_config_version=1
    )
    different_snapshot_version = build_legacy_settlement_message(
        **common, notary_config=config_v1, notary_config_version=2
    )

    assert len(pinned_v1) == len(different_snapshot_address) == len(different_snapshot_version) == 235
    assert pinned_v1 != different_snapshot_address
    assert pinned_v1 != different_snapshot_version
    assert pinned_v1.startswith(b"PROPHET_RESOLVE_V2")


def test_completed_bundle_passes_existing_threshold_validation(tmp_path, monkeypatch):
    service, _, job, threshold, _, _, _, _ = _service(tmp_path, monkeypatch)
    result = service.sign_agreed_job(job.job_id)
    threshold.validate_bundle(result.signature_bundle, result.canonical_message)


def test_completed_bundle_is_compatible_with_existing_ed25519_instruction_builder(tmp_path, monkeypatch):
    service, _, job, _, _, _, _, _ = _service(tmp_path, monkeypatch)
    result = service.sign_agreed_job(job.job_id)
    from prophet_sdk.ed25519 import build_ed25519_ix
    for signature, public_key in (
        (result.signature_bundle.signer_a_signature, result.signature_bundle.signer_a_public_key),
        (result.signature_bundle.signer_b_signature, result.signature_bundle.signer_b_public_key),
    ):
        ix = build_ed25519_ix(result.canonical_message, signature, bytes(Pubkey.from_string(public_key)))
        assert bytes(ix.data)[16:48] == bytes(Pubkey.from_string(public_key))
        assert bytes(ix.data)[48:112] == signature
        assert bytes(ix.data)[112:] == result.canonical_message


def test_coordinator_history_is_unchanged_by_signing(tmp_path, monkeypatch):
    service, store, job, _, _, _, _, _ = _service(tmp_path, monkeypatch)
    before = store.get_job(job.job_id)
    service.sign_agreed_job(job.job_id)
    after = store.get_job(job.job_id)
    assert after == before and after.state == AGREED


def test_link_is_durable_and_proves_bundle_provenance_after_restart(tmp_path, monkeypatch):
    service, _, job, _, journal, _, _, _ = _service(tmp_path, monkeypatch)
    result = service.sign_agreed_job(job.job_id)
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    link = reopened.get_coordinator_link(job.job_id)
    intent = reopened.get_for_coordinator_job(job.job_id)
    assert link.signing_scope_id == result.signing_intent_id
    assert link.canonical_message_digest == result.canonical_message_digest == intent.canonical_message_digest
    assert intent.state == BOTH_SIGNED and intent.signer_a_result and intent.signer_b_result


def test_coordinator_v1_schema_migrates_without_retroactively_binding_terminal_history(tmp_path):
    path = tmp_path / "coordinator-v1.sqlite"
    store, job, *_ = _state(path, terminal="AGREED", bind_context=False)
    store.close()
    db = sqlite3.connect(path)
    db.execute("DROP TABLE resolution_job_solana_bindings")
    db.execute("DROP TABLE resolution_job_settlement_contexts")
    db.execute("DELETE FROM schema_migrations WHERE version IN (2, 3)")
    db.execute("PRAGMA user_version = 1")
    db.commit(); db.close()

    definition, evidence = _canonical_inputs()
    a = _verification(definition, evidence, slot="A")
    b = _verification(definition, evidence, slot="B")
    reopened = ResolutionCoordinatorStore(
        path, verifier_a=VerifierBinding("A", a["verifier"]), verifier_b=VerifierBinding("B", b["verifier"])
    )
    assert reopened.schema_version() == 3
    assert reopened.get_job(job.job_id).state == AGREED
    with pytest.raises(CoordinatorRejected, match="settlement_context_binding_too_late"):
        reopened.bind_settlement_context(job.job_id, _context())
    reopened.close()


def test_signing_journal_v1_schema_migrates_and_adds_durable_coordinator_link(tmp_path, monkeypatch):
    threshold, journal, a, b, transport = signing_fixture(tmp_path, monkeypatch)
    message = _message_for_journal_migration()
    intent = journal.reserve_intent(message, signer_a=_bindings(a, b)[0], signer_b=_bindings(a, b)[1])
    journal.close()
    path = tmp_path / "journal.sqlite"
    db = sqlite3.connect(path)
    db.execute("DROP TABLE coordinator_signing_links")
    db.execute("PRAGMA user_version = 1")
    db.commit(); db.close()

    reopened = SigningJournal(path)
    assert reopened.get(intent.signing_scope_id).canonical_message == message
    rehydrated = ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened)
    linked = rehydrated.prepare_2_of_2(message, coordinator_job_id=H(91))
    assert linked.signing_scope_id == intent.signing_scope_id
    assert reopened.get_coordinator_link(H(91)).signing_scope_id == intent.signing_scope_id
    assert transport.calls == []
    reopened.close()


def _message_for_journal_migration():
    return build_legacy_settlement_message(
        program_id="11111111111111111111111111111111",
        market="11111111111111111111111111111111",
        notary_config="11111111111111111111111111111111",
        resolver_hash=H(4), open_ts=-7, resolve_ts=42, notary_config_version=9,
        outcome="INVALID", proof_hash=H(5), public_inputs_hash=H(6),
    )


def test_settlement_context_persists_full_u64_notary_config_version(tmp_path):
    store, job, *_ = _state(tmp_path / "u64.sqlite", terminal="PENDING", bind_context=False)
    context = _context(notary_config_version=(1 << 64) - 1)
    assert store.bind_settlement_context(job.job_id, context) == context
    assert store.get_settlement_context(job.job_id) == context
    store.close()
