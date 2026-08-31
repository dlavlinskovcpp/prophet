import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from src.audit import JsonlAuditLogger
from src.attester import AttesterService
from src.resolver_v2_pipeline import (
    AcquiredEvidence,
    AcquisitionRequest,
    BundleContext,
    EquivocationStore,
    PipelineRejected,
    SignerPolicy,
    SignerPolicyEngine,
    ThresholdSigningGate,
    VerificationReport,
    ResolverV2Pipeline,
    build_legacy_settlement_message,
    build_resolution_bundle,
    normalize_evidence,
    verification_result_from_report,
)
from src.signer_backend import SignerBackend


H = lambda byte: f"{byte:02x}" * 32


class RecordingVaultCompatibleBackend(SignerBackend):
    """Exercises the same narrow sign(pubkey, message, context) backend API."""

    name = "vault_transit_compatible_fake"

    def __init__(self):
        self.calls = []

    def sign(self, pubkey, message, context):
        self.calls.append((str(pubkey), message, dict(context)))
        return b"s" * 64


class StaticAcquirer:
    def acquire(self, request):
        return AcquiredEvidence(request.adapter_digest, request.resolver_id, request.source_id, "100", b"verified-input", {"round": "1"})


class StaticVerifier:
    def __init__(self, verifier):
        self.descriptor = verifier

    def verify(self, definition, evidence, trust_model):
        return VerificationReport(
            outcome="YES", status="VERIFIED", confidence="high", verifier=self.descriptor,
            checks=[{"check_id": "proof", "status": "PASS", "expected_commitment": H(4), "observed_commitment": H(4), "detail_hash": H(5)}],
            verified_facts={"round": "1"}, observed_at_ms="110", valid_from_ms="100", valid_until_ms="1000",
        )


def _objects():
    adapter = {
        "schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0",
        "adapter_id": "prophet.resolver.zktls", "adapter_version": "2.0.0", "implementation_digest": H(1),
    }
    trust = {
        "schema": "prophet.trust-model-descriptor.v2", "schema_version": "2.0.0",
        "trust_model_id": "zktls-test", "trust_model_version": "2.0.0", "document_hash": H(2),
    }
    definition = {
        "schema": "prophet.resolver-definition.v2", "schema_version": "2.0.0",
        "resolver_id": "test-resolver", "resolver_type": "zktls", "adapter": adapter,
        "trust_model": trust, "source": {"source_id": "test-source"},
        "verification_policy": {"proof_required": True}, "evaluation": {"expression": "integer_eq"},
        "timing": {"not_before_ms": "0", "observation_deadline_ms": "999999", "max_evidence_age_ms": "1000"},
        "conflict_policy": {"mode": "reject"}, "fallback_policy": {"outcome": "INVALID"},
    }
    verifier = {
        "schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0",
        "adapter_id": "prophet.verifier.independent", "adapter_version": "2.0.0", "implementation_digest": H(3),
    }
    return definition, trust, verifier


def _bundle(outcome="YES"):
    definition, trust, verifier = _objects()
    from prophet_sdk import resolver_v2
    definition_hash = resolver_v2.resolver_definition_hash(definition).hex()
    evidence = normalize_evidence(
        AcquiredEvidence(H(1), "test-resolver", "test-source", "100", b'{"price":"42"}', {"round": "7"}, "99", "7"),
        definition_hash=definition_hash, collector={"instance_id": "collector-1"},
        transport={"kind": "zktls"}, provenance={"proof": "present"},
    )
    report = VerificationReport(
        outcome=outcome, status="VERIFIED", confidence="high", verifier=verifier,
        checks=[{"check_id": "proof", "status": "PASS", "expected_commitment": H(4), "observed_commitment": H(4), "detail_hash": H(5)}],
        verified_facts={"price": "42"}, observed_at_ms="110", valid_from_ms="100", valid_until_ms="1000",
    )
    result = verification_result_from_report(definition_hash=definition_hash, evidence=evidence, report=report)
    context = BundleContext(
        market=H(10), cluster_genesis_hash=H(11), settlement_program_id=H(12), notary_config=H(13),
        notary_config_version="7", resolution_nonce=H(14), observed_at_ms="120", valid_until_ms="1000",
        signer_policy={"policy_id": "test-policy", "policy_version": "2.0.0", "threshold": "2", "allowed_adapter_digest": H(3)},
    )
    return build_resolution_bundle(definition=definition, evidence=[evidence], verification_results=[result], trust_model=trust, verifier=verifier, outcome=outcome, context=context)


def _policy(bundle):
    return SignerPolicy(
        policy_id="test-policy", policy_version="2.0.0", allowed_resolver_ids=("test-resolver",),
        allowed_adapter_digests=(H(1),), allowed_trust_model_digests=(bundle["trust_model_digest"],),
        allowed_verifier_ids=("prophet.verifier.independent",), allowed_verifier_versions=("2.0.0",),
        max_evidence_age_ms=100, max_verification_age_ms=100, market=bundle["market"],
        cluster_genesis_hash=bundle["cluster_genesis_hash"], signer_set_version="2.0.0", threshold=2,
    )


def _message(bundle):
    return build_legacy_settlement_message(
        program_id="11111111111111111111111111111111", market="11111111111111111111111111111111",
        notary_config="11111111111111111111111111111111", resolver_hash=bundle["resolver_definition_hash"],
        open_ts=-5, resolve_ts=9, notary_config_version=7, outcome=bundle["outcome"], proof_hash=H(20), public_inputs_hash=H(21),
    )


def test_pipeline_is_deterministic_and_legacy_message_is_unchanged(tmp_path):
    first, second = _bundle(), _bundle()
    from prophet_sdk import resolver_v2
    assert first == second
    assert resolver_v2.resolution_bundle_hash(first) == resolver_v2.resolution_bundle_hash(second)
    message = _message(first)
    expected = (b"PROPHET_RESOLVE_V2" + bytes(32) * 3 + bytes.fromhex(first["resolver_definition_hash"])
                + (-5).to_bytes(8, "little", signed=True) + (9).to_bytes(8, "little", signed=True)
                + (7).to_bytes(8, "little") + b"\x01" + bytes.fromhex(H(20)) + bytes.fromhex(H(21)))
    assert message == expected
    assert len(message) == 235
    legacy_service = SimpleNamespace(client=SimpleNamespace(program_id=Pubkey.default()))
    assert message == AttesterService._build_message_v2(
        legacy_service, Pubkey.default(), Pubkey.default(), bytes.fromhex(first["resolver_definition_hash"]),
        -5, 9, 7, 1, bytes.fromhex(H(20)), bytes.fromhex(H(21)),
    )


def test_explicit_acquisition_normalization_and_verification_stages():
    definition, trust, verifier = _objects()
    from prophet_sdk import resolver_v2
    pipeline = ResolverV2Pipeline(StaticAcquirer(), StaticVerifier(verifier))
    evidence = pipeline.acquire_and_normalize(
        AcquisitionRequest("test-resolver", H(1), "test-source", "100", H(22)),
        definition_hash=resolver_v2.resolver_definition_hash(definition).hex(),
        collector={"instance_id": "test"}, transport={"kind": "zktls"}, provenance={"proof": "present"},
    )
    report, result = pipeline.verify(definition, evidence, trust)
    assert report.outcome == "YES"
    assert result["result"] == "VERIFIED"
    assert result["evidence_hash"] == resolver_v2.evidence_hash(evidence).hex()


@pytest.mark.parametrize("mutation,reason", [
    (lambda b: b.__setitem__("market", H(99)), "market_mismatch"),
    (lambda b: b.__setitem__("cluster_genesis_hash", H(98)), "cluster_mismatch"),
])
def test_policy_rejects_unknown_and_wrong_bindings(mutation, reason):
    bundle = _bundle()
    policy = _policy(bundle)
    mutation(bundle)
    assert SignerPolicyEngine(policy).evaluate(bundle, now_ms=120).reason == reason


def test_policy_rejects_unknown_resolver_and_trust_model():
    bundle = _bundle()
    policy = _policy(bundle)
    assert SignerPolicyEngine(replace(policy, allowed_resolver_ids=("other-resolver",))).evaluate(bundle, now_ms=120).reason == "unknown_resolver"
    assert SignerPolicyEngine(replace(policy, allowed_trust_model_digests=(H(99),))).evaluate(bundle, now_ms=120).reason == "unknown_trust_model"


def test_policy_rejects_inner_verifier_digest_not_in_local_trust_policy():
    bundle = _bundle()
    policy = replace(
        _policy(bundle),
        trusted_verifier_implementations=(("prophet.verifier.independent", "2.0.0", H(3)),),
    )
    bundle["verification_results"][0]["verifier"] = {
        **bundle["verification_results"][0]["verifier"],
        "implementation_digest": H(9),
    }
    assert SignerPolicyEngine(policy).evaluate(bundle, now_ms=120).reason == "untrusted_verifier_implementation"


def test_policy_rejects_stale_tampered_and_wrong_verifier():
    bundle = _bundle()
    policy = _policy(bundle)
    assert SignerPolicyEngine(policy).evaluate(bundle, now_ms=1000).reason == "stale_evidence"
    assert SignerPolicyEngine(policy).evaluate(bundle, now_ms=120, expected_bundle_hash=H(0)).reason == "bundle_hash_mismatch"
    bundle["verifier"]["adapter_id"] = "unexpected"
    assert SignerPolicyEngine(policy).evaluate(bundle, now_ms=120).reason == "unexpected_verifier"
    tampered = _bundle()
    tampered["evidence"][0]["payload_hex"] = "00"
    assert SignerPolicyEngine(_policy(_bundle())).evaluate(tampered, now_ms=120).reason.startswith("invalid_bundle:")


def test_policy_requires_two_independent_agreeing_verifiers():
    single = _bundle()
    definition, evidence, trust = single["resolver_definition"], single["evidence"][0], single["trust_model"]
    verifier_b = {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": "prophet.verifier.independent-b", "adapter_version": "2.0.0", "implementation_digest": H(30)}
    report_b = VerificationReport("YES", "VERIFIED", "high", [{"check_id": "proof", "status": "PASS", "expected_commitment": H(4), "observed_commitment": H(4), "detail_hash": H(5)}], verifier_b, {"price": "42"}, "110", "100", "1000")
    result_b = verification_result_from_report(definition_hash=single["resolver_definition_hash"], evidence=evidence, report=report_b)
    context = BundleContext(single["market"], single["cluster_genesis_hash"], single["settlement_program_id"], single["notary_config"], single["notary_config_version"], single["resolution_nonce"], single["observed_at_ms"], single["valid_until_ms"], single["signer_policy"])
    multi = build_resolution_bundle(definition=definition, evidence=[evidence], verification_results=[single["verification_results"][0], result_b], trust_model=trust, verifier=single["verifier"], outcome="YES", context=context)
    policy = replace(_policy(single), allowed_verifier_ids=("prophet.verifier.independent", "prophet.verifier.independent-b"), required_verifier_count=2, required_verifier_ids=("prophet.verifier.independent", "prophet.verifier.independent-b"), minimum_agreeing_verifiers=2)
    assert SignerPolicyEngine(policy).evaluate(multi, now_ms=120).allowed
    assert SignerPolicyEngine(policy).evaluate(single, now_ms=120).reason == "required_verifier_set_incomplete"


def test_signer_gate_is_idempotent_rejects_equivocation_and_hides_raw_evidence(tmp_path):
    bundle = _bundle()
    backend = RecordingVaultCompatibleBackend()
    gate = ThresholdSigningGate(
        backend, SignerPolicyEngine(_policy(bundle)), EquivocationStore(str(tmp_path / "equivocation.jsonl")),
        JsonlAuditLogger(str(tmp_path / "audit.jsonl"), "test"),
    )
    from prophet_sdk import resolver_v2
    expected = resolver_v2.resolution_bundle_hash(bundle).hex()
    auth = gate.authorize(bundle, now_ms=120, expected_bundle_hash=expected, settlement_message=_message(bundle))
    retry = gate.authorize(bundle, now_ms=120, expected_bundle_hash=expected, settlement_message=_message(bundle))
    assert auth.bundle_hash == retry.bundle_hash
    signatures = gate.sign(auth, [Keypair().pubkey()])
    assert list(signatures.values()) == [b"s" * 64]
    context = backend.calls[0][2]
    assert "payload_hex" not in json.dumps(context)
    assert context["bundle_hash"] == expected
    conflicting = _bundle("NO")
    with pytest.raises(PipelineRejected, match="equivocation_conflicting_outcome"):
        gate.authorize(conflicting, now_ms=120, expected_bundle_hash=None, settlement_message=_message(conflicting))


def test_signer_equivocation_is_rejected_before_backend_signing(tmp_path):
    from src.resolver_v2_multi_verifier import EquivocationMonitor

    bundle = _bundle()
    backend = RecordingVaultCompatibleBackend()
    monitor = EquivocationMonitor(str(tmp_path / "monitor.jsonl"))
    signer = Keypair().pubkey()
    domain = ":".join((bundle["market"], bundle["cluster_genesis_hash"], bundle["notary_config"], bundle["notary_config_version"], bundle["resolution_nonce"]))
    assert not monitor.observe_signer(str(signer), domain=domain, outcome="NO", bundle_hash=H(99), resolver=bundle["resolver_definition_hash"], market=bundle["market"], timestamp_ms="110")
    gate = ThresholdSigningGate(backend, SignerPolicyEngine(_policy(bundle)), EquivocationStore(str(tmp_path / "store.jsonl")), JsonlAuditLogger(str(tmp_path / "audit.jsonl"), "test"), equivocation_monitor=monitor)
    auth = gate.authorize(bundle, now_ms=120, expected_bundle_hash=None, settlement_message=_message(bundle))
    with pytest.raises(PipelineRejected, match="signer_equivocation_detected"):
        gate.sign(auth, [signer])
    assert backend.calls == []
