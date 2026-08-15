from dataclasses import replace

import pytest
from solders.keypair import Keypair

from src.resolver_v2_adapters import (
    OracleKeyEpoch, OracleKeyring, SequenceReplayGuard, SignedOracleAdapter,
    SignedOracleMaterial, ZkTlsAdapter, ZkTlsClaims, ZkTlsMaterial,
    signed_oracle_message,
)
from src.resolver_v2_pipeline import (
    BundleContext, PipelineRejected, ResolverV2Pipeline, build_legacy_settlement_message,
    build_resolution_bundle, normalize_evidence,
)

from prophet_sdk import resolver_v2


H = lambda byte: f"{byte:02x}" * 32


class DeterministicProofVerifier:
    def __init__(self, valid=True):
        self.valid = valid

    def verify(self, *, proof_bytes, response_bytes, expected_binding):
        return ZkTlsClaims(self.valid, "1", "api.example", H(30), H(31), __import__("hashlib").sha256(response_bytes).hexdigest(), "bad proof")


def _adapter(adapter_id, digest):
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": adapter_id, "adapter_version": "2.0.0", "implementation_digest": digest}


def _trust():
    return {"schema": "prophet.trust-model-descriptor.v2", "schema_version": "2.0.0", "trust_model_id": "trusted-model", "trust_model_version": "2.0.0", "document_hash": H(2)}


def _definition(kind, adapter, source):
    return {
        "schema": "prophet.resolver-definition.v2", "schema_version": "2.0.0", "resolver_id": f"{kind}-resolver", "resolver_type": kind,
        "adapter": adapter, "trust_model": _trust(), "source": source,
        "verification_policy": {"fail_closed": True}, "evaluation": {"mode": "bound"},
        "timing": {"not_before_ms": "0", "observation_deadline_ms": "999999", "max_evidence_age_ms": "100"},
        "conflict_policy": {"mode": "reject"}, "fallback_policy": {"outcome": "INVALID"},
    }


def _zktls_definition(adapter=None, selector="data.outcome"):
    adapter = adapter or _adapter("prophet.resolver.zktls", H(1))
    return _definition("zktls", adapter, {
        "source_domain": "api.example", "request_definition_hash": H(30), "response_selector": selector,
        "predicate": {"allowed_outcomes": ["YES", "NO", "INVALID"]}, "response_schema": "example.response", "response_schema_version": "1",
        "proof_version": "1", "cluster_genesis_hash": H(31), "max_evidence_age_ms": "50",
    })


def _zktls_evidence(definition=None, verifier=None, now=100):
    definition = definition or _zktls_definition()
    adapter = ZkTlsAdapter(adapter_digest=H(1), verifier_descriptor=_adapter("prophet.verifier.zktls", H(3)), proof_verifier=verifier or DeterministicProofVerifier(), clock_ms=lambda: now)
    material = ZkTlsMaterial(b"proof", b'{"schema":"example.response","schema_version":"1","data":{"outcome":"YES"}}', "1", "90", "api.example", H(30), H(31))
    acquired = adapter.acquire(definition, material)
    evidence = normalize_evidence(acquired, definition_hash=resolver_v2.resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "zktls"}, provenance={"proof_hash": H(8)})
    return definition, adapter, evidence


def test_zktls_valid_and_pipeline_binding():
    definition, adapter, evidence = _zktls_evidence()
    pipeline = ResolverV2Pipeline(acquirer=None, verifier=adapter)  # Acquisition is already adapter-bound.
    report, result = pipeline.verify(definition, evidence, _trust())
    assert report.status == "VERIFIED" and report.outcome == "YES"
    assert result["result"] == "VERIFIED"


@pytest.mark.parametrize("case", ["invalid_proof", "wrong_selector", "stale", "malformed", "resolver", "trust"])
def test_zktls_fails_closed(case):
    definition, adapter, evidence = _zktls_evidence(verifier=DeterministicProofVerifier(valid=case != "invalid_proof"), now=1000 if case == "stale" else 100)
    if case == "wrong_selector":
        definition, adapter, evidence = _zktls_evidence(definition=_zktls_definition(selector="data.missing"))
    elif case == "malformed":
        definition, adapter, evidence = _zktls_evidence()
        evidence["payload_hex"] = resolver_v2.canonical_json_bytes({"proof_hex": "00"}).hex()
    elif case == "resolver":
        evidence["definition_hash"] = H(99)
    trust = _trust()
    if case == "trust":
        trust = {**trust, "document_hash": H(99)}
    assert adapter.verify(definition, evidence, trust).status == "REJECTED"


def test_zktls_rejects_wrong_domain_adapter_and_unsupported_version():
    definition = _zktls_definition()
    adapter = ZkTlsAdapter(adapter_digest=H(1), verifier_descriptor=_adapter("prophet.verifier.zktls", H(3)), proof_verifier=DeterministicProofVerifier())
    with pytest.raises(PipelineRejected, match="binding"):
        adapter.acquire(definition, ZkTlsMaterial(b"p", b"{}", "1", "1", "wrong.example", H(30), H(31)))
    with pytest.raises(PipelineRejected, match="version"):
        adapter.acquire(definition, ZkTlsMaterial(b"p", b"{}", "2", "1", "api.example", H(30), H(31)))
    with pytest.raises(PipelineRejected, match="adapter_digest"):
        adapter.acquire(_zktls_definition(_adapter("prophet.resolver.zktls", H(9))), ZkTlsMaterial(b"p", b"{}", "1", "1", "api.example", H(30), H(31)))


def _oracle_source():
    return {"message_domain": "PROPHET_SIGNED_ORACLE_V2", "payload_schema": "prophet.signed-oracle-observation.v2", "payload_schema_version": "2.0.0", "market": H(40), "cluster_genesis_hash": H(41), "replay_domain": H(42), "key_set_version": "1.0.0", "max_message_age_ms": "50", "outcome_mapping": {"yes": "YES", "no": "NO"}, "require_monotonic_sequence": True}


def _oracle_definition():
    return _definition("signed_oracle", _adapter("prophet.resolver.signed-oracle", H(4)), _oracle_source())


def _oracle_payload(definition, outcome="yes", timestamp="90", sequence="1", **overrides):
    payload = {"schema": "prophet.signed-oracle-observation.v2", "schema_version": "2.0.0", "resolver_id": definition["resolver_id"], "market": H(40), "outcome": outcome, "source_timestamp_ms": timestamp, "sequence": sequence, "cluster_genesis_hash": H(41), "replay_domain": H(42)}
    payload.update(overrides)
    return payload


def _oracle_evidence(*, keypair=None, adapter=None, payload=None, key_id="old", now=100):
    definition = _oracle_definition()
    keypair = keypair or Keypair()
    keyring = OracleKeyring([OracleKeyEpoch("old", str(keypair.pubkey()), "1.0.0", "0", "1000")])
    adapter = adapter or SignedOracleAdapter(adapter_digest=H(4), verifier_descriptor=_adapter("prophet.verifier.signed-oracle", H(5)), keyring=keyring, clock_ms=lambda: now)
    payload = payload or _oracle_payload(definition)
    message = signed_oracle_message(payload)
    acquired = adapter.acquire(definition, SignedOracleMaterial(payload, bytes(keypair.sign_message(message)), key_id, "1.0.0", str(now)))
    evidence = normalize_evidence(acquired, definition_hash=resolver_v2.resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "signed"}, provenance={"signature_scheme": "ed25519"})
    return definition, adapter, evidence, keypair


def test_signed_oracle_valid_signature_and_pipeline_to_legacy_message():
    definition, adapter, evidence, _ = _oracle_evidence()
    report, result = ResolverV2Pipeline(None, adapter).verify(definition, evidence, _trust())
    assert report.status == "VERIFIED" and report.outcome == "YES"
    context = BundleContext(H(40), H(41), H(43), H(44), "1", H(45), "100", "140", {"policy_id": "p", "policy_version": "1.0.0", "threshold": "1", "allowed_adapter_digest": H(5)})
    bundle = build_resolution_bundle(definition=definition, evidence=[evidence], verification_results=[result], trust_model=_trust(), verifier=_adapter("prophet.verifier.signed-oracle", H(5)), outcome="YES", context=context)
    before = build_legacy_settlement_message(program_id="11111111111111111111111111111111", market="11111111111111111111111111111111", notary_config="11111111111111111111111111111111", resolver_hash=bundle["resolver_definition_hash"], open_ts=0, resolve_ts=1, notary_config_version=1, outcome="YES", proof_hash=H(50), public_inputs_hash=H(51))
    after = build_legacy_settlement_message(program_id="11111111111111111111111111111111", market="11111111111111111111111111111111", notary_config="11111111111111111111111111111111", resolver_hash=bundle["resolver_definition_hash"], open_ts=0, resolve_ts=1, notary_config_version=1, outcome="YES", proof_hash=H(50), public_inputs_hash=H(51))
    assert before == after


def test_legacy_oracle_keyring_direct_construction_remains_supported():
    definition = _oracle_definition()
    keypair = Keypair()
    keyring = OracleKeyring([OracleKeyEpoch("old", str(keypair.pubkey()), "1.0.0", "0", "1000")])
    adapter = SignedOracleAdapter(adapter_digest=H(4), verifier_descriptor=_adapter("prophet.verifier.signed-oracle", H(5)), keyring=keyring, clock_ms=lambda: 100)
    payload = _oracle_payload(definition)
    evidence = normalize_evidence(adapter.acquire(definition, SignedOracleMaterial(payload, bytes(keypair.sign_message(signed_oracle_message(payload))), "old", "1.0.0", "100")), definition_hash=resolver_v2.resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "signed"}, provenance={"signature_scheme": "ed25519"})
    assert adapter.verify(definition, evidence, _trust()).status == "VERIFIED"


@pytest.mark.parametrize("case", ["invalid_signature", "wrong_key", "stale", "wrong_market", "wrong_resolver", "wrong_cluster", "wrong_schema", "replay"])
def test_signed_oracle_fail_closed_replay_domains(case):
    definition, adapter, evidence, keypair = _oracle_evidence(now=200 if case == "stale" else 100)
    if case == "invalid_signature":
        raw = resolver_v2.parse_canonical_json(bytes.fromhex(evidence["payload_hex"]))
        raw["signature_hex"] = "00" * 64
        evidence["payload_hex"] = resolver_v2.canonical_json_bytes(raw).hex()
        evidence["payload_hash"] = __import__("hashlib").sha256(bytes.fromhex(evidence["payload_hex"])).hexdigest()
    elif case == "wrong_key":
        payload = _oracle_payload(definition)
        message = signed_oracle_message(payload)
        acquired = adapter.acquire(definition, SignedOracleMaterial(payload, bytes(Keypair().sign_message(message)), "old", "1.0.0", "100"))
        evidence = normalize_evidence(acquired, definition_hash=resolver_v2.resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "signed"}, provenance={"signature_scheme": "ed25519"})
    elif case in {"wrong_market", "wrong_resolver", "wrong_cluster"}:
        field = {"wrong_market": "market", "wrong_resolver": "resolver_id", "wrong_cluster": "cluster_genesis_hash"}[case]
        payload = _oracle_payload(definition, **{field: H(99) if field != "resolver_id" else "other-resolver"})
        with pytest.raises(PipelineRejected):
            _oracle_evidence(keypair=keypair, adapter=adapter, payload=payload)
        return
    elif case == "wrong_schema":
        with pytest.raises(PipelineRejected):
            signed_oracle_message({**_oracle_payload(definition), "schema_version": "9.0.0"})
        return
    result = adapter.verify(definition, evidence, _trust())
    assert result.status == "REJECTED" if case != "replay" else result.status == "VERIFIED"
    if case == "replay":
        assert adapter.verify(definition, evidence, _trust()).status == "REJECTED"


def test_signed_oracle_key_rotation_boundaries_and_conflicting_outcomes():
    old, new = Keypair(), Keypair()
    keyring = OracleKeyring([OracleKeyEpoch("old", str(old.pubkey()), "1.0.0", "0", "100"), OracleKeyEpoch("new", str(new.pubkey()), "1.0.0", "100")])
    adapter = SignedOracleAdapter(adapter_digest=H(4), verifier_descriptor=_adapter("prophet.verifier.signed-oracle", H(5)), keyring=keyring, clock_ms=lambda: 100)
    definition = _oracle_definition()
    # The old key is valid before, but not at, the explicit rotation boundary.
    old_payload = _oracle_payload(definition, timestamp="99", sequence="1")
    _, old_adapter, old_evidence, _ = _oracle_evidence(keypair=old, adapter=adapter, payload=old_payload)
    assert old_adapter.verify(definition, old_evidence, _trust()).status == "VERIFIED"
    boundary = _oracle_payload(definition, timestamp="100", sequence="2")
    _, _, old_boundary_evidence, _ = _oracle_evidence(keypair=old, adapter=adapter, payload=boundary)
    assert adapter.verify(definition, old_boundary_evidence, _trust()).status == "REJECTED"
    _, new_adapter, new_evidence, _ = _oracle_evidence(keypair=new, adapter=adapter, payload=boundary, key_id="new")
    assert new_adapter.verify(definition, new_evidence, _trust()).status == "VERIFIED"
    conflicting = _oracle_payload(definition, outcome="no", timestamp="100", sequence="2")
    _, _, conflict_evidence, _ = _oracle_evidence(keypair=new, adapter=adapter, payload=conflicting, key_id="new")
    assert adapter.verify(definition, conflict_evidence, _trust()).status == "REJECTED"
