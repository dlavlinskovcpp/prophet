import hashlib
from dataclasses import replace

import pytest

from src.resolver_v2_pipeline import PipelineRejected, normalize_evidence, verification_result_from_report
from prophet_sdk import resolver_v2
from src.resolver_v2_independent_verifier import IndependentOracleVerifier
from src.resolver_v2_multi_verifier import AgreementPolicy, ConflictStateStore, MultiVerifierCoordinator
from src.resolver_v2_oracle_adapters import (
    ChainlinkAdapter, ChainlinkMaterial, PythAdapter, PythMaterial,
    evaluate_numeric_predicate,
)

H = lambda b: f"{b:02x}" * 32


def descriptor(name, digest):
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": name, "adapter_version": "2.0.0", "implementation_digest": H(digest)}


def trust():
    return {"schema": "prophet.trust-model-descriptor.v2", "schema_version": "2.0.0", "trust_model_id": "oracle-trust", "trust_model_version": "2.0.0", "document_hash": H(9)}


PREDICATE = {"operator": ">=", "threshold_value": "12345", "threshold_exponent": "-2", "outcome_if_true": "YES", "outcome_if_false": "NO"}


def definition(kind):
    source = ({"feed_id": H(1), "network": "solana-mainnet", "cluster_genesis_hash": H(2), "price_exponent": "-2", "max_publish_age_ms": "50", "max_confidence_bps": "100", "predicate": PREDICATE, "outcome_mapping": {"numeric_predicate": "v1"}, "account_schema_version": "pyth-price-v2", "adapter_version": "2.0.0"}
              if kind == "pyth" else
              {"feed_id": H(1), "network": "solana-mainnet", "cluster_genesis_hash": H(2), "decimals": "2", "max_answer_age_ms": "50", "require_round_metadata": True, "predicate": PREDICATE, "outcome_mapping": {"numeric_predicate": "v1"}, "data_source_version": "chainlink-solana-v1", "adapter_version": "2.0.0"})
    return {"schema": "prophet.resolver-definition.v2", "schema_version": "2.0.0", "resolver_id": f"{kind}-feed", "resolver_type": kind, "adapter": descriptor(f"prophet.resolver.{kind}", 3), "trust_model": trust(), "source": source, "verification_policy": {"fail_closed": True}, "evaluation": {"mode": "numeric-v1"}, "timing": {"not_before_ms": "0", "observation_deadline_ms": "999999", "max_evidence_age_ms": "50"}, "conflict_policy": {"mode": "reject"}, "fallback_policy": {"outcome": "INVALID"}}


def evidence(kind, *, value="12345", timestamp="90", **changes):
    d = definition(kind)
    if kind == "pyth":
        adapter = PythAdapter(adapter_digest=H(3), verifier_descriptor=descriptor("prophet.verifier.pyth.primary", 4), clock_ms=lambda: 100)
        material = PythMaterial(H(1), "solana-mainnet", H(2), value, "-2", "10", "TRADING", timestamp, "77", b"pyth-account", "100")
    else:
        adapter = ChainlinkAdapter(adapter_digest=H(3), verifier_descriptor=descriptor("prophet.verifier.chainlink.primary", 4), clock_ms=lambda: 100)
        material = ChainlinkMaterial(H(1), "solana-mainnet", H(2), value, "2", timestamp, "77", "77", b"chainlink-account", "100")
    material = replace(material, **changes)
    acquired = adapter.acquire(d, material)
    return d, adapter, normalize_evidence(acquired, definition_hash=resolver_v2.resolver_definition_hash(d).hex(), collector={"implementation": "test"}, transport={"kind": kind}, provenance={"raw_data_hash": hashlib.sha256(material.raw_data).hexdigest()})


@pytest.mark.parametrize("kind", ["pyth", "chainlink"])
@pytest.mark.parametrize("value,outcome", [("12344", "NO"), ("12345", "YES"), ("12346", "YES")])
def test_numeric_threshold_boundaries_and_pipeline_evidence(kind, value, outcome):
    d, adapter, e = evidence(kind, value=value)
    report = adapter.verify(d, e, trust())
    assert report.status == "VERIFIED" and report.outcome == outcome
    assert report.verified_facts["feed_id"] == H(1) and report.verified_facts["raw_data_hash"]


@pytest.mark.parametrize("kind,field,value", [
    ("pyth", "publish_time_ms", "1"), ("pyth", "status", "HALTED"), ("pyth", "confidence", "1000"),
    ("chainlink", "updated_at_ms", "1"), ("chainlink", "answered_in_round", "1"),
])
def test_oracle_staleness_confidence_and_update_fail_closed(kind, field, value):
    d, adapter, e = evidence(kind, **{field: value})
    assert adapter.verify(d, e, trust()).status == "REJECTED"


@pytest.mark.parametrize("kind", ["pyth", "chainlink"])
@pytest.mark.parametrize("mutation", ["wrong_feed", "wrong_network", "wrong_cluster", "malformed", "resolver", "trust"])
def test_oracle_binding_and_malformed_rejections(kind, mutation):
    d, adapter, e = evidence(kind)
    if mutation == "resolver": e["definition_hash"] = H(99)
    elif mutation == "trust": d = {**d, "trust_model": {**trust(), "document_hash": H(99)}}
    elif mutation == "malformed": e["payload_hex"] = resolver_v2.canonical_json_bytes({"x": "y"}).hex()
    else:
        row = resolver_v2.parse_canonical_json(bytes.fromhex(e["payload_hex"]))
        key = {"wrong_feed": "feed_id", "wrong_network": "network", "wrong_cluster": "cluster_genesis_hash"}[mutation]
        row[key] = H(99) if key != "network" else "other-network"
        e["payload_hex"] = resolver_v2.canonical_json_bytes(row).hex()
    assert adapter.verify(d, e, trust()).status == "REJECTED"


def test_fixed_point_exponent_boundaries_and_cross_adapter_predicate_equivalence():
    assert evaluate_numeric_predicate("12345", "-2", PREDICATE) == evaluate_numeric_predicate("12345", "-2", PREDICATE) == "YES"
    assert evaluate_numeric_predicate("12344", "-2", PREDICATE) == "NO"
    with pytest.raises(PipelineRejected, match="overflow"):
        evaluate_numeric_predicate(str((1 << 127) - 1), "255", {**PREDICATE, "threshold_exponent": "-255"})
    with pytest.raises(PipelineRejected): evaluate_numeric_predicate("1", "256", PREDICATE)


@pytest.mark.parametrize("kind", ["pyth", "chainlink"])
def test_independent_verifier_agrees_on_same_canonical_evidence(kind, tmp_path):
    d, primary, e = evidence(kind)
    independent = IndependentOracleVerifier(descriptor(f"prophet.verifier.{kind}.independent", 5), clock_ms=lambda: 100)
    first, second = primary.verify(d, e, trust()), independent.verify(d, e, trust())
    assert first.status == second.status == "VERIFIED" and first.outcome == second.outcome
    results = [verification_result_from_report(definition_hash=e["definition_hash"], evidence=e, report=r) for r in (first, second)]
    policy = AgreementPolicy((first.verifier["adapter_id"], second.verifier["adapter_id"]), 2, 2)
    assert MultiVerifierCoordinator(policy, ConflictStateStore(str(tmp_path / "conflicts.jsonl"))).evaluate({"market": H(6), "resolver_definition_hash": e["definition_hash"], "cluster_genesis_hash": H(2), "notary_config": H(7), "notary_config_version": "1", "resolution_nonce": H(8), "verification_results": results}, now_ms=100, attempt_id="ok", timestamp_ms="100").allowed


def test_oracle_disagreement_is_persistent_and_fails_closed(tmp_path):
    d, adapter, e = evidence("pyth")
    primary = verification_result_from_report(definition_hash=e["definition_hash"], evidence=e, report=adapter.verify(d, e, trust()))
    independent = verification_result_from_report(definition_hash=e["definition_hash"], evidence=e, report=IndependentOracleVerifier(descriptor("prophet.verifier.pyth.independent", 5), clock_ms=lambda: 100).verify(d, e, trust()))
    facts = resolver_v2.parse_canonical_json(bytes.fromhex(independent["verified_facts_hex"])); facts["outcome"] = "NO"; independent["verified_facts_hex"] = resolver_v2.canonical_json_bytes(facts).hex(); independent["verified_facts_hash"] = hashlib.sha256(bytes.fromhex(independent["verified_facts_hex"])).hexdigest()
    bundle = {"market": H(6), "resolver_definition_hash": e["definition_hash"], "cluster_genesis_hash": H(2), "notary_config": H(7), "notary_config_version": "1", "resolution_nonce": H(8), "verification_results": [primary, independent]}
    state = ConflictStateStore(str(tmp_path / "conflicts.jsonl")); decision = MultiVerifierCoordinator(AgreementPolicy((primary["verifier"]["adapter_id"], independent["verifier"]["adapter_id"]), 2, 2), state).evaluate(bundle, now_ms=100, attempt_id="conflict", timestamp_ms="100")
    assert not decision.allowed and decision.reason == "outcome_conflict" and state.is_open(bundle)
