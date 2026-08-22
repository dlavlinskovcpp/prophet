import copy
import hashlib

import pytest

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from src.resolver_v2_pipeline import resolver_v2
from src.resolution_coordinator_store import (
    AGREED,
    A_RECORDED,
    B_RECORDED,
    CONFLICT,
    CoordinatorRejected,
    ResolutionCoordinatorStore,
    VerifierBinding,
)


H = lambda value: f"{value:02x}" * 32


def _fixture(path):
    from tests.test_dual_verifier_runtime_independence import _runtimes

    namespace, definition, evidence, runtime_a, runtime_b, *_ = _runtimes()
    result_a = runtime_a.verify(
        resolver_definition=definition, evidence=evidence, trust_model=namespace["_trust"]()
    )
    result_b = runtime_b.verify(
        resolver_definition=definition, evidence=evidence, trust_model=namespace["_trust"]()
    )
    store = ResolutionCoordinatorStore(
        path,
        verifier_a=VerifierBinding("A", result_a["verifier"]),
        verifier_b=VerifierBinding("B", result_b["verifier"]),
    )
    return store, definition, evidence, result_a, result_b


def _disagrees(result, outcome="NO"):
    changed = copy.deepcopy(result)
    facts = resolver_v2.parse_canonical_json(bytes.fromhex(changed["verified_facts_hex"]))
    facts["outcome"] = outcome
    encoded = resolver_v2.canonical_json_bytes(facts)
    changed["verified_facts_hex"] = encoded.hex()
    changed["verified_facts_hash"] = hashlib.sha256(encoded).hexdigest()
    resolver_v2.validate_verification_result(changed)
    return changed


def _job(store, definition, evidence):
    return store.register_job(market=H(1), resolver_definition=definition, evidence=evidence)


def test_database_initializes_and_records_schema_version(tmp_path):
    store, *_ = _fixture(tmp_path / "coordinator.sqlite")
    assert store.schema_version() == 4
    assert (tmp_path / "coordinator.sqlite").exists()
    store.close()


def test_job_registration_is_deterministic_and_security_relevant(tmp_path):
    store, definition, evidence, *_ = _fixture(tmp_path / "coordinator.sqlite")
    first = _job(store, definition, evidence)
    assert _job(store, definition, evidence).job_id == first.job_id
    different = copy.deepcopy(evidence)
    different["evidence_id"] = H(99)
    resolver_v2.validate_evidence_envelope(different)
    assert _job(store, definition, different).job_id != first.job_id
    store.close()


def test_records_each_slot_idempotently_and_reaches_agreement(tmp_path):
    store, definition, evidence, result_a, result_b = _fixture(tmp_path / "coordinator.sqlite")
    job = _job(store, definition, evidence)
    assert store.record_result(job_id=job.job_id, slot="A", result=result_a).state == A_RECORDED
    assert store.record_result(job_id=job.job_id, slot="A", result=result_a).state == A_RECORDED
    assert store.record_result(job_id=job.job_id, slot="B", result=result_b).state == AGREED
    assert store.record_result(job_id=job.job_id, slot="B", result=result_b).state == AGREED
    final = store.get_job(job.job_id)
    assert final.outcome == "YES" and final.verifier_a_result == result_a and final.verifier_b_result == result_b
    store.close()


def test_disagreement_is_persisted_as_terminal_conflict(tmp_path):
    store, definition, evidence, result_a, result_b = _fixture(tmp_path / "coordinator.sqlite")
    job = _job(store, definition, evidence)
    store.record_result(job_id=job.job_id, slot="A", result=result_a)
    final = store.record_result(job_id=job.job_id, slot="B", result=_disagrees(result_b))
    assert final.state == CONFLICT and final.conflict_reason == "same_evidence_different_outcome"
    store.close()


@pytest.mark.parametrize("slot", ("A", "B"))
def test_different_second_slot_result_fails_closed_and_persists_conflict(tmp_path, slot):
    store, definition, evidence, result_a, result_b = _fixture(tmp_path / f"{slot}.sqlite")
    job = _job(store, definition, evidence)
    result = result_a if slot == "A" else result_b
    store.record_result(job_id=job.job_id, slot=slot, result=result)
    with pytest.raises(CoordinatorRejected, match="verifier_slot_equivocation"):
        store.record_result(job_id=job.job_id, slot=slot, result=_disagrees(result))
    assert store.get_job(job.job_id).state == CONFLICT
    store.close()


def test_rejects_wrong_verifier_and_result_job_binding(tmp_path):
    store, definition, evidence, result_a, result_b = _fixture(tmp_path / "coordinator.sqlite")
    job = _job(store, definition, evidence)
    with pytest.raises(CoordinatorRejected, match="unexpected_verifier_identity"):
        store.record_result(job_id=job.job_id, slot="B", result=result_a)
    mismatched = copy.deepcopy(result_b)
    mismatched["definition_hash"] = H(9)
    resolver_v2.validate_verification_result(mismatched)
    with pytest.raises(CoordinatorRejected, match="verification_result_job_binding_mismatch"):
        store.record_result(job_id=job.job_id, slot="B", result=mismatched)
    store.close()


def test_restart_after_partial_and_agreed_state_preserves_history(tmp_path):
    path = tmp_path / "coordinator.sqlite"
    store, definition, evidence, result_a, result_b = _fixture(path)
    job = _job(store, definition, evidence)
    store.record_result(job_id=job.job_id, slot="A", result=result_a)
    store.close()

    reopened = ResolutionCoordinatorStore(
        path,
        verifier_a=VerifierBinding("A", result_a["verifier"]),
        verifier_b=VerifierBinding("B", result_b["verifier"]),
    )
    assert reopened.get_job(job.job_id).state == A_RECORDED
    assert reopened.record_result(job_id=job.job_id, slot="B", result=result_b).state == AGREED
    reopened.close()

    final = ResolutionCoordinatorStore(
        path,
        verifier_a=VerifierBinding("A", result_a["verifier"]),
        verifier_b=VerifierBinding("B", result_b["verifier"]),
    )
    assert final.get_job(job.job_id).state == AGREED
    final.close()


def test_completed_job_does_not_allow_result_rewrite(tmp_path):
    store, definition, evidence, result_a, result_b = _fixture(tmp_path / "coordinator.sqlite")
    job = _job(store, definition, evidence)
    store.record_result(job_id=job.job_id, slot="A", result=result_a)
    store.record_result(job_id=job.job_id, slot="B", result=result_b)
    with pytest.raises(CoordinatorRejected, match="completed_job_result_immutable"):
        store.record_result(job_id=job.job_id, slot="A", result=_disagrees(result_a))
    assert store.get_job(job.job_id).state == AGREED
    store.close()
