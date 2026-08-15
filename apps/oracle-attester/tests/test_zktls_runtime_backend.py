import hashlib

import pytest

from src.resolver_v2_adapters import ZkTlsAdapter, ZkTlsClaims, ZkTlsMaterial
from src.resolver_v2_pipeline import PipelineRejected, normalize_evidence
from src.runtime_config import RuntimeConfigError, parse_runtime_config
from src.zktls_runtime_backend import DeterministicTestZkTlsProofVerifier
from prophet_sdk import resolver_v2


H = lambda byte: f"{byte:02x}" * 32


def _adapter():
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": "prophet.resolver.zktls", "adapter_version": "2.0.0", "implementation_digest": H(1)}


def _verifier():
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": "prophet.verifier.zktls", "adapter_version": "2.0.0", "implementation_digest": H(3)}


def _trust():
    return {"schema": "prophet.trust-model-descriptor.v2", "schema_version": "2.0.0", "trust_model_id": "trusted-model", "trust_model_version": "2.0.0", "document_hash": H(2)}


def _definition(proof_version="1"):
    return {"schema": "prophet.resolver-definition.v2", "schema_version": "2.0.0", "resolver_id": "zktls-resolver", "resolver_type": "zktls", "adapter": _adapter(), "trust_model": _trust(), "source": {"source_domain": "api.example", "request_definition_hash": H(30), "response_selector": "data.outcome", "predicate": {"allowed_outcomes": ["YES", "NO", "INVALID"]}, "response_schema": "example.response", "response_schema_version": "1", "proof_version": proof_version, "cluster_genesis_hash": H(31), "max_evidence_age_ms": "50"}, "verification_policy": {"fail_closed": True}, "evaluation": {"mode": "bound"}, "timing": {"not_before_ms": "0", "observation_deadline_ms": "999999", "max_evidence_age_ms": "100"}, "conflict_policy": {"mode": "reject"}, "fallback_policy": {"outcome": "INVALID"}}


def _runtime_raw(*, mode="test", backend="deterministic-test", versions=None, include_zktls=True):
    raw = {"schema_version": 1, "environment": "public-devnet", "mode": mode, "solana": {"cluster": "devnet", "genesis_hash": "g", "prophet_program_id": "p"}, "resolver_v2": {"schema_version": 2}, "verifier": {"implementation_id": "zktls-runtime", "version": "2"}, "allowed_adapters": ["zktls"], "limits": {"request_max_bytes": 1, "request_timeout_seconds": 1}, "freshness": {"default_max_evidence_age_seconds": 1, "default_max_verification_age_seconds": 1}, "internal_auth": {"token_env": "TOKEN"}}
    if include_zktls:
        raw["zktls"] = {"provider_id": "deterministic-provider", "verifier_backend": backend, "allowed_proof_versions": versions or ["1"]}
    return raw


def _evidence(adapter, *, proof=b"proof"):
    definition = _definition()
    acquired = adapter.acquire(definition, ZkTlsMaterial(proof, b'{"schema":"example.response","schema_version":"1","data":{"outcome":"YES"}}', "1", "90", "api.example", H(30), H(31)))
    return normalize_evidence(acquired, definition_hash=resolver_v2.resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "zktls"}, provenance={"proof_hash": H(8)})


def test_zktls_runtime_test_backend_verifies_valid_fixture():
    adapter = ZkTlsAdapter.from_runtime(runtime_config=parse_runtime_config(_runtime_raw()), resolver_definition=_definition(), verifier_descriptor=_verifier(), clock_ms=lambda: 100)
    assert isinstance(adapter.proof_verifier, DeterministicTestZkTlsProofVerifier)
    assert adapter.verify(_definition(), _evidence(adapter), _trust()).status == "VERIFIED"


def test_zktls_runtime_test_backend_rejects_invalid_proof():
    adapter = ZkTlsAdapter.from_runtime(runtime_config=parse_runtime_config(_runtime_raw()), resolver_definition=_definition(), verifier_descriptor=_verifier(), clock_ms=lambda: 100)
    report = adapter.verify(_definition(), _evidence(adapter, proof=b"invalid"), _trust())
    assert report.status == "REJECTED" and report.failure_code == "invalid_proof"


class _CapturingVerifier:
    def __init__(self, *, valid=True, raises=False): self.binding = None; self.valid = valid; self.raises = raises
    def verify(self, *, proof_bytes, response_bytes, expected_binding):
        if self.raises: raise RuntimeError("backend unavailable")
        self.binding = expected_binding
        return ZkTlsClaims(self.valid, expected_binding.proof_version, expected_binding.source_domain, expected_binding.request_definition_hash, expected_binding.cluster_genesis_hash, hashlib.sha256(response_bytes).hexdigest())


def test_zktls_proof_backend_receives_expected_binding_and_failures_reject():
    verifier = _CapturingVerifier()
    adapter = ZkTlsAdapter(adapter_digest=H(1), verifier_descriptor=_verifier(), proof_verifier=verifier, clock_ms=lambda: 100)
    evidence = _evidence(adapter)
    assert adapter.verify(_definition(), evidence, _trust()).status == "VERIFIED"
    assert verifier.binding.resolver_id == "zktls-resolver" and verifier.binding.source_domain == "api.example"
    assert verifier.binding.request_definition_hash == H(30) and verifier.binding.cluster_genesis_hash == H(31)
    assert verifier.binding.proof_version == "1" and verifier.binding.acquired_at_ms == "90"
    assert verifier.binding.evidence_payload_hash == hashlib.sha256(bytes.fromhex(evidence["payload_hex"])).hexdigest()
    failed = ZkTlsAdapter(adapter_digest=H(1), verifier_descriptor=_verifier(), proof_verifier=_CapturingVerifier(valid=False), clock_ms=lambda: 100)
    errored = ZkTlsAdapter(adapter_digest=H(1), verifier_descriptor=_verifier(), proof_verifier=_CapturingVerifier(raises=True), clock_ms=lambda: 100)
    assert failed.verify(_definition(), _evidence(failed), _trust()).status == "REJECTED"
    error_report = errored.verify(_definition(), _evidence(errored), _trust())
    assert error_report.status == "REJECTED" and error_report.failure_code == "proof_verifier_error"


def test_zktls_runtime_unknown_backend_and_unsupported_version_reject():
    unknown = parse_runtime_config(_runtime_raw(backend="unknown"))
    with pytest.raises(PipelineRejected): ZkTlsAdapter.from_runtime(runtime_config=unknown, resolver_definition=_definition(), verifier_descriptor=_verifier())
    with pytest.raises(PipelineRejected): ZkTlsAdapter.from_runtime(runtime_config=parse_runtime_config(_runtime_raw()), resolver_definition=_definition("2"), verifier_descriptor=_verifier())


@pytest.mark.parametrize("mutate", [lambda raw: raw.pop("zktls"), lambda raw: raw["zktls"].pop("provider_id"), lambda raw: raw["zktls"].pop("verifier_backend"), lambda raw: raw["zktls"].pop("allowed_proof_versions"), lambda raw: raw["zktls"].update({"unknown": "x"}), lambda raw: raw["zktls"].update({"allowed_proof_versions": []})])
def test_zktls_runtime_config_rejects_missing_or_malformed_section(mutate):
    raw = _runtime_raw(); mutate(raw)
    with pytest.raises(RuntimeConfigError): parse_runtime_config(raw)


def test_zktls_runtime_config_rejects_test_backend_in_production_and_fingerprints_config():
    with pytest.raises(RuntimeConfigError): parse_runtime_config(_runtime_raw(mode="production"))
    first = parse_runtime_config(_runtime_raw(versions=["1", "2"]))
    second = parse_runtime_config(_runtime_raw(versions=["2", "1"]))
    changed = parse_runtime_config(_runtime_raw(versions=["1"]))
    assert first.fingerprint() == second.fingerprint() and first.fingerprint() != changed.fingerprint()
