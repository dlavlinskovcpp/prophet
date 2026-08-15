import copy
import hashlib

import pytest

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from src.resolver_v2_pipeline import resolver_v2
from src.resolution_coordinator import (
    ResolutionCoordinator,
    ResolutionCoordinatorConfigurationError,
    ResolutionCoordinatorVerifierFailure,
)
from src.resolution_coordinator_store import (
    AGREED,
    A_RECORDED,
    CONFLICT,
    ResolutionCoordinatorStore,
    VerifierBinding,
)
from src.runtime_config import CoordinatorVerifierServiceConfig
from src.verifier_service_client import VerifierClientTransportError


H = lambda byte: f"{byte:02x}" * 32


class _Client:
    def __init__(self, slot, descriptor, answers):
        self.slot = slot
        self.config = CoordinatorVerifierServiceConfig(
            f"http://verifier-{slot.lower()}.internal",
            f"{slot}_TOKEN",
            descriptor["adapter_id"],
            descriptor["adapter_version"],
            descriptor["implementation_digest"],
            1,
        )
        self.answers = list(answers)
        self.calls = []

    def verify(self, **request):
        self.calls.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def _fixture(path, a_answers=None, b_answers=None):
    from tests.test_dual_verifier_runtime_independence import _runtimes

    namespace, definition, evidence, runtime_a, runtime_b, *_ = _runtimes()
    trust = namespace["_trust"]()
    result_a = runtime_a.verify(resolver_definition=definition, evidence=evidence, trust_model=trust)
    result_b = runtime_b.verify(resolver_definition=definition, evidence=evidence, trust_model=trust)
    store = ResolutionCoordinatorStore(path, verifier_a=VerifierBinding("A", result_a["verifier"]), verifier_b=VerifierBinding("B", result_b["verifier"]))
    client_a = _Client("A", result_a["verifier"], a_answers if a_answers is not None else [result_a])
    client_b = _Client("B", result_b["verifier"], b_answers if b_answers is not None else [result_b])
    return ResolutionCoordinator(state=store, verifier_client_a=client_a, verifier_client_b=client_b), store, client_a, client_b, definition, evidence, trust, result_a, result_b


def _resolve(coordinator, definition, evidence, trust):
    return coordinator.resolve(market=H(1), resolver_definition=definition, evidence=evidence, trust_model=trust, correlation_id="request-1")


def _result_with(result, *, outcome, status):
    changed = copy.deepcopy(result)
    facts = resolver_v2.parse_canonical_json(bytes.fromhex(changed["verified_facts_hex"]))
    facts.update({"outcome": outcome, "status": status})
    encoded = resolver_v2.canonical_json_bytes(facts)
    changed.update({"result": status, "verified_facts_hex": encoded.hex(), "verified_facts_hash": hashlib.sha256(encoded).hexdigest()})
    resolver_v2.validate_verification_result(changed)
    return changed


def test_new_job_calls_a_then_b_persists_results_and_agrees(tmp_path):
    coordinator, _, client_a, client_b, definition, evidence, trust, *_ = _fixture(tmp_path / "state.sqlite")
    result = _resolve(coordinator, definition, evidence, trust)
    assert result.state == AGREED and len(client_a.calls) == len(client_b.calls) == 1
    assert client_a.calls[0]["request_id"] == client_b.calls[0]["request_id"] == "request-1"


def test_canonical_disagreement_and_invalid_results_are_persisted_by_state_core(tmp_path):
    coordinator, _, _, _, definition, evidence, trust, result_a, result_b = _fixture(tmp_path / "conflict.sqlite", b_answers=[])
    coordinator.verifier_client_b.answers = [_result_with(result_b, outcome="NO", status="VERIFIED")]
    conflict = _resolve(coordinator, definition, evidence, trust)
    assert conflict.state == CONFLICT and conflict.conflict_reason == "same_evidence_different_outcome"

    invalid_a = _result_with(result_a, outcome="INVALID", status="REJECTED")
    invalid_b = _result_with(result_b, outcome="INVALID", status="REJECTED")
    invalid, _, _, _, definition, evidence, trust, *_ = _fixture(tmp_path / "invalid.sqlite", a_answers=[invalid_a], b_answers=[invalid_b])
    persisted = _resolve(invalid, definition, evidence, trust)
    assert persisted.state == CONFLICT and persisted.conflict_reason == "invalid_vs_valid"
    assert persisted.verifier_a_result["result"] == persisted.verifier_b_result["result"] == "REJECTED"


def test_a_transport_failure_leaves_resumable_job_and_never_calls_b(tmp_path):
    coordinator, store, client_a, client_b, definition, evidence, trust, *_ = _fixture(tmp_path / "state.sqlite", a_answers=[VerifierClientTransportError("down")])
    with pytest.raises(ResolutionCoordinatorVerifierFailure, match="verifier_a_service_failure"):
        _resolve(coordinator, definition, evidence, trust)
    job = store.register_job(market=H(1), resolver_definition=definition, evidence=evidence)
    assert job.state == "PENDING" and job.verifier_a_result is None and client_a.calls and not client_b.calls


def test_b_failure_persists_a_and_resume_calls_only_b_after_restart(tmp_path):
    path = tmp_path / "state.sqlite"
    coordinator, store, client_a, client_b, definition, evidence, trust, result_a, result_b = _fixture(path, b_answers=[VerifierClientTransportError("down")])
    with pytest.raises(ResolutionCoordinatorVerifierFailure, match="verifier_b_service_failure"):
        _resolve(coordinator, definition, evidence, trust)
    job = store.register_job(market=H(1), resolver_definition=definition, evidence=evidence)
    assert job.state == A_RECORDED and job.verifier_a_result == result_a and job.verifier_b_result is None
    store.close()

    reopened = ResolutionCoordinatorStore(path, verifier_a=VerifierBinding("A", result_a["verifier"]), verifier_b=VerifierBinding("B", result_b["verifier"]))
    resume_a, resume_b = _Client("A", result_a["verifier"], [result_a]), _Client("B", result_b["verifier"], [result_b])
    resumed = ResolutionCoordinator(state=reopened, verifier_client_a=resume_a, verifier_client_b=resume_b)
    assert _resolve(resumed, definition, evidence, trust).state == AGREED
    assert not resume_a.calls and len(resume_b.calls) == 1
    assert len(client_a.calls) == len(client_b.calls) == 1
    reopened.close()


def test_terminal_jobs_and_exact_repeated_resolution_make_no_new_calls(tmp_path):
    coordinator, _, client_a, client_b, definition, evidence, trust, *_ = _fixture(tmp_path / "agreed.sqlite")
    first = _resolve(coordinator, definition, evidence, trust)
    second = _resolve(coordinator, definition, evidence, trust)
    assert first == second and first.state == AGREED and len(client_a.calls) == len(client_b.calls) == 1

    conflict, _, conflict_a, conflict_b, definition, evidence, trust, _, result_b = _fixture(tmp_path / "conflict.sqlite", b_answers=[])
    conflict.verifier_client_b.answers = [_result_with(result_b, outcome="NO", status="VERIFIED")]
    assert _resolve(conflict, definition, evidence, trust).state == CONFLICT
    assert _resolve(conflict, definition, evidence, trust).state == CONFLICT
    assert len(conflict_a.calls) == len(conflict_b.calls) == 1


def test_identity_routing_rejects_cross_wired_clients_before_resolution(tmp_path):
    _, store, _, _, _, _, _, result_a, result_b = _fixture(tmp_path / "state.sqlite")
    with pytest.raises(ResolutionCoordinatorConfigurationError, match="slot_mismatch"):
        ResolutionCoordinator(state=store, verifier_client_a=_Client("B", result_b["verifier"], []), verifier_client_b=_Client("B", result_b["verifier"], []))
    with pytest.raises(ResolutionCoordinatorConfigurationError, match="identity_mismatch"):
        ResolutionCoordinator(state=store, verifier_client_a=_Client("A", result_b["verifier"], []), verifier_client_b=_Client("B", result_b["verifier"], []))
    store.close()
