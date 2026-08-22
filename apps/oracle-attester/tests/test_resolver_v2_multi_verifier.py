import hashlib

import pytest

from src.resolver_v2_independent_verifier import IndependentProofClaims, IndependentZkTlsVerifier
from src.resolver_v2_multi_verifier import AgreementPolicy, ConflictStateStore, EquivocationMonitor, evaluate_agreement
from src.resolver_v2_pipeline import PipelineRejected, VerificationReport, verification_result_from_report

from prophet_sdk import resolver_v2


H = lambda b: f"{b:02x}" * 32


def descriptor(name, version="2.0.0", digest=3):
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": name, "adapter_version": version, "implementation_digest": H(digest)}


def result(verifier_id, outcome="YES", evidence_hash=H(8), valid_until="200", version="2.0.0"):
    facts = resolver_v2.canonical_json_bytes({"confidence": "high", "failure_code": None, "outcome": outcome, "status": "VERIFIED", "verified_facts": {"value": "fixed"}})
    return {"schema": "prophet.verification-result.v2", "schema_version": "2.0.0", "definition_hash": H(7), "evidence_hash": evidence_hash,
            "verifier": descriptor(verifier_id, version), "result": "VERIFIED", "checks": [{"check_id": "proof", "status": "PASS", "expected_commitment": H(1), "observed_commitment": H(1), "detail_hash": H(2)}],
            "verified_facts_hex": facts.hex(), "verified_facts_hash": hashlib.sha256(facts).hexdigest(), "observed_at_ms": "100", "valid_from_ms": "100", "valid_until_ms": valid_until, "finality": None}


POLICY = AgreementPolicy(("verifier-a", "verifier-b"), 2, 2, True)


def test_two_independent_verifiers_agree_deterministically():
    rows = [result("verifier-a"), result("verifier-b")]
    first = evaluate_agreement(rows, POLICY, now_ms=150)
    for _ in range(128):
        assert evaluate_agreement(list(reversed(rows)), POLICY, now_ms=150) == first
    assert first.allowed and first.canonical_outcome == "YES"


@pytest.mark.parametrize("rows,reason", [
    ([result("verifier-a")], "required_verifier_set_incomplete"),
    ([result("verifier-a"), result("verifier-b", outcome="NO")], "outcome_conflict"),
    ([result("verifier-a"), result("verifier-b", evidence_hash=H(9))], "evidence_hash_conflict"),
    ([result("verifier-a", valid_until="99"), result("verifier-b", valid_until="200")], "stale_verification_result"),
    ([result("verifier-a"), result("verifier-a", version="9.0.0")], "duplicate_verifier_identity"),
])
def test_adversarial_agreement_rejections(rows, reason):
    assert evaluate_agreement(rows, POLICY, now_ms=150).reason == reason


def bundle(rows):
    return {"market": H(10), "resolver_definition_hash": H(7), "cluster_genesis_hash": H(11), "notary_config": H(12), "notary_config_version": "1", "resolution_nonce": H(13), "verification_results": rows}


def test_conflict_persists_across_retries_and_requires_fresh_evidence(tmp_path):
    conflict = ConflictStateStore(str(tmp_path / "conflicts.jsonl"))
    candidate = bundle([result("verifier-a"), result("verifier-b", outcome="NO")])
    decision = evaluate_agreement(candidate["verification_results"], POLICY)
    conflict.open(candidate, decision, "attempt-1", "100")
    assert conflict.is_open(candidate)
    reloaded = ConflictStateStore(str(tmp_path / "conflicts.jsonl"))
    assert reloaded.is_open(candidate)
    with pytest.raises(PipelineRejected, match="requires_fresh"):
        reloaded.clear(candidate, fresh_evidence=True, policy_override=False, attempt_id="retry", timestamp_ms="101")
    fresh = bundle([result("verifier-a", evidence_hash=H(99)), result("verifier-b", evidence_hash=H(99))])
    reloaded.clear(fresh, fresh_evidence=True, policy_override=False, attempt_id="fresh", timestamp_ms="102")
    assert not reloaded.is_open(fresh)


def test_verifier_and_signer_equivocation_are_persistent(tmp_path):
    monitor = EquivocationMonitor(str(tmp_path / "equivocation.jsonl"))
    row = result("verifier-a")
    assert not monitor.observe_verifier(row, domain="domain", bundle_hash=H(20), market=H(10), timestamp_ms="100")
    assert monitor.observe_verifier(result("verifier-a", outcome="NO"), domain="domain", bundle_hash=H(21), market=H(10), timestamp_ms="101")
    assert not monitor.observe_signer("signer-a", domain="domain", outcome="YES", bundle_hash=H(20), resolver=H(7), market=H(10), timestamp_ms="100")
    assert monitor.observe_signer("signer-a", domain="domain", outcome="NO", bundle_hash=H(21), resolver=H(7), market=H(10), timestamp_ms="101")


class IndependentChecker:
    def validate(self, proof, response):
        return IndependentProofClaims(True, "1", "api.example", H(30), H(31), hashlib.sha256(response).hexdigest())


def test_independent_verifier_path_does_not_use_primary_adapter():
    trust = {"schema": "prophet.trust-model-descriptor.v2", "schema_version": "2.0.0", "trust_model_id": "trust", "trust_model_version": "2.0.0", "document_hash": H(2)}
    definition = {"schema": "prophet.resolver-definition.v2", "schema_version": "2.0.0", "resolver_id": "independent-zktls", "resolver_type": "zktls", "adapter": descriptor("adapter-zktls", digest=1), "trust_model": trust,
                  "source": {"source_domain": "api.example", "request_definition_hash": H(30), "response_selector": "data.outcome", "predicate": {"allowed_outcomes": ["YES"]}, "response_schema": "schema", "response_schema_version": "1", "proof_version": "1", "cluster_genesis_hash": H(31), "max_evidence_age_ms": "50"},
                  "verification_policy": {"x": "y"}, "evaluation": {"x": "y"}, "timing": {"not_before_ms": "0", "observation_deadline_ms": "999", "max_evidence_age_ms": "50"}, "conflict_policy": {"x": "y"}, "fallback_policy": {"x": "y"}}
    response = b'{"schema":"schema","schema_version":"1","data":{"outcome":"YES"}}'
    raw = resolver_v2.canonical_json_bytes({"cluster_genesis_hash": H(31), "proof_hex": "aa", "proof_version": "1", "request_definition_hash": H(30), "response_hex": response.hex(), "source_domain": "api.example"})
    evidence = {"definition_hash": resolver_v2.resolver_definition_hash(definition).hex(), "acquired_at_ms": "100", "payload_hex": raw.hex()}
    verifier = IndependentZkTlsVerifier(descriptor("verifier-independent", digest=9), IndependentChecker(), clock_ms=lambda: 120)
    report = verifier.verify(definition, evidence, trust)
    assert report.status == "VERIFIED" and report.verifier["adapter_id"] == "verifier-independent"
