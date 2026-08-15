from pathlib import Path

import pytest

from src.independent_zktls_runtime_factory import IndependentZkTlsRuntimeFactory
from src.resolver_v2_independent_verifier import IndependentProofClaims
from src.resolver_v2_pipeline import PipelineRejected, normalize_evidence
from src.resolver_verifier_runtime import ResolverVerifierRuntime
from src.runtime_adapter_factory import RuntimeAdapterFactory, RuntimeAdapterRegistry
from src.runtime_config import parse_runtime_config


H = lambda byte: f"{byte:02x}" * 32


def _descriptor(identity, digest):
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": identity, "adapter_version": "2.0.0", "implementation_digest": H(digest)}


def _config(identity):
    return parse_runtime_config({"schema_version": 1, "environment": "public-devnet", "mode": "test", "solana": {"cluster": "devnet", "genesis_hash": "g", "prophet_program_id": "p"}, "resolver_v2": {"schema_version": 2}, "verifier": {"implementation_id": identity, "version": "2.0.0"}, "allowed_adapters": ["zktls"], "zktls": {"provider_id": "deterministic-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]}, "limits": {"request_max_bytes": 1, "request_timeout_seconds": 1}, "freshness": {"default_max_evidence_age_seconds": 1, "default_max_verification_age_seconds": 1}, "internal_auth": {"token_env": "TOKEN"}})


class _CountingPrimaryFactory(RuntimeAdapterFactory):
    def __init__(self, **kwargs): super().__init__(**kwargs); self.calls = 0
    def create(self, resolver_definition): self.calls += 1; return super().create(resolver_definition)


class _CountingIndependentChecker:
    def __init__(self): self.calls = 0
    def validate(self, proof, response):
        self.calls += 1
        return IndependentProofClaims(True, "1", "api.example", H(30), H(31), __import__("hashlib").sha256(response).hexdigest())


class _CountingIndependentFactory(IndependentZkTlsRuntimeFactory):
    def __init__(self, **kwargs): super().__init__(**kwargs); self.calls = 0
    def create(self, resolver_definition): self.calls += 1; return super().create(resolver_definition)


def _runtimes():
    namespace = {}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition, _, evidence = namespace["_zktls_evidence"]()
    descriptor_a, descriptor_b = _descriptor("prophet.verifier.runtime.a", 70), _descriptor("prophet.verifier.runtime.b", 71)
    config_a, config_b = _config(descriptor_a["adapter_id"]), _config(descriptor_b["adapter_id"])
    registry = RuntimeAdapterRegistry()
    primary_factory = _CountingPrimaryFactory(runtime_config=config_a, verifier_descriptors={"zktls": descriptor_a}, registry=registry, clock_ms=lambda: 100)
    checker = _CountingIndependentChecker()
    independent_factory = _CountingIndependentFactory(runtime_config=config_b, verifier_descriptor=descriptor_b, checker=checker, registry=registry, clock_ms=lambda: 100)
    return namespace, definition, evidence, ResolverVerifierRuntime(config_a, primary_factory, descriptor_a), ResolverVerifierRuntime(config_b, independent_factory, descriptor_b), primary_factory, independent_factory, checker


def test_dual_verifier_runtimes_accept_same_canonical_request_and_agree():
    namespace, definition, evidence, runtime_a, runtime_b, primary_factory, independent_factory, checker = _runtimes()
    original = (definition.copy(), evidence.copy(), namespace["_trust"]().copy())
    fingerprints = (runtime_a.runtime_config.fingerprint(), runtime_b.runtime_config.fingerprint())
    identities = (dict(runtime_a.verifier_descriptor), dict(runtime_b.verifier_descriptor))
    shared_registry = primary_factory.registry
    result_a = runtime_a.verify(resolver_definition=definition, evidence=evidence, trust_model=namespace["_trust"]())
    result_b = runtime_b.verify(resolver_definition=definition, evidence=evidence, trust_model=namespace["_trust"]())
    assert result_a["result"] == result_b["result"] == "VERIFIED"
    assert result_a["verifier"]["adapter_id"] != result_b["verifier"]["adapter_id"]
    assert (definition, evidence, namespace["_trust"]()) == original
    assert primary_factory.calls == 1 and independent_factory.calls == 1 and checker.calls == 1
    assert (runtime_a.runtime_config.fingerprint(), runtime_b.runtime_config.fingerprint()) == fingerprints
    assert (dict(runtime_a.verifier_descriptor), dict(runtime_b.verifier_descriptor)) == identities
    assert primary_factory.registry is independent_factory.registry is shared_registry


def test_dual_verifier_runtime_identity_mismatch_fails_closed():
    _, _, _, runtime_a, _, _, _, _ = _runtimes()
    with pytest.raises(PipelineRejected): ResolverVerifierRuntime(_config("prophet.verifier.runtime.b"), runtime_a.adapter_factory, runtime_a.verifier_descriptor)


def test_primary_failure_does_not_mutate_or_block_independent_runtime():
    namespace, definition, evidence, runtime_a, runtime_b, primary_factory, independent_factory, checker = _runtimes()
    primary_adapter = runtime_a.adapter_factory.create(definition)
    acquired = primary_adapter.acquire(definition, namespace["ZkTlsMaterial"](b"invalid", b'{"schema":"example.response","schema_version":"1","data":{"outcome":"YES"}}', "1", "90", "api.example", H(30), H(31)))
    invalid = normalize_evidence(acquired, definition_hash=namespace["resolver_v2"].resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "zktls"}, provenance={"proof_hash": H(8)})
    assert runtime_a.verify(resolver_definition=definition, evidence=invalid, trust_model=namespace["_trust"]())["result"] == "REJECTED"
    assert runtime_b.verify(resolver_definition=definition, evidence=evidence, trust_model=namespace["_trust"]())["result"] == "VERIFIED"
    assert independent_factory.calls == 1 and checker.calls == 1 and primary_factory.calls >= 2
