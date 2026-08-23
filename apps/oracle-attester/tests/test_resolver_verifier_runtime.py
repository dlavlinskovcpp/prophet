from dataclasses import replace
from pathlib import Path
import tempfile

import pytest
from solders.keypair import Keypair

from src.resolver_v2_adapters import ZkTlsMaterial
from src.resolver_v2_pipeline import PipelineRejected, normalize_evidence
from src.resolver_verifier_runtime import ResolverVerifierRuntime
from src.runtime_adapter_factory import RuntimeAdapterFactory
from src.runtime_config import parse_runtime_config
from src.signed_oracle_runtime_keys import load_trusted_oracle_key_registry
from src.verifier_attestation import VerifierAttestationSigner, verify_attestation


H = lambda byte: f"{byte:02x}" * 32


def _runtime_descriptor(name="prophet.verifier.runtime.a"):
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": name, "adapter_version": "2.0.0", "implementation_digest": H(70)}


def _raw(allowed, *, zktls=None, signed_oracle=None, mode="test"):
    raw = {"schema_version": 1, "environment": "public-devnet", "mode": mode, "solana": {"cluster": "devnet", "genesis_hash": "g", "prophet_program_id": "p"}, "resolver_v2": {"schema_version": 2}, "verifier": {"implementation_id": "prophet.verifier.runtime.a", "version": "2.0.0"}, "allowed_adapters": allowed, "limits": {"request_max_bytes": 1, "request_timeout_seconds": 1}, "freshness": {"default_max_evidence_age_seconds": 1, "default_max_verification_age_seconds": 1}, "internal_auth": {"token_env": "TOKEN"}}
    if zktls is not None: raw["zktls"] = zktls
    if signed_oracle is not None: raw["signed_oracle"] = signed_oracle
    return raw


def _helpers():
    adapters, oracles = {}, {}
    exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), adapters)
    exec(Path(__file__).with_name("test_resolver_v2_oracle_adapters.py").read_text(), oracles)
    return adapters, oracles


def _runtime(config, *, signed_registry=None):
    descriptor = _runtime_descriptor()
    factory = RuntimeAdapterFactory(runtime_config=config, verifier_descriptors={kind: descriptor for kind in ("zktls", "signed_oracle", "pyth", "chainlink")}, signed_oracle_registry=signed_registry, clock_ms=lambda: 100)
    return ResolverVerifierRuntime(config, factory, descriptor)


def test_runtime_verify_zktls_uses_configured_backend():
    adapters, _ = _helpers(); definition, _, evidence = adapters["_zktls_evidence"]()
    config = parse_runtime_config(_raw(["zktls"], zktls={"provider_id": "deterministic-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]}))
    result = _runtime(config).verify(resolver_definition=definition, evidence=evidence, trust_model=adapters["_trust"]())
    assert result["result"] == "VERIFIED" and result["verifier"] == _runtime_descriptor()


def test_runtime_verify_signed_oracle_uses_registry_backed_keyring():
    adapters, _ = _helpers(); definition, _, evidence, keypair = adapters["_oracle_evidence"]()
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path = Path(root) / "registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "{keypair.pubkey()}"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        config = parse_runtime_config(_raw(["signed-oracle"], mode="production", signed_oracle={"registry_path": str(path), "key_bindings": [{"key_id": "old", "key_set_version": "1.0.0", "oracle_identity": "oracle"}]}))
        runtime = _runtime(config, signed_registry=load_trusted_oracle_key_registry(path))
        result = runtime.verify(resolver_definition=definition, evidence=evidence, trust_model=adapters["_trust"]())
        assert result["result"] == "VERIFIED" and result["verifier"] == _runtime_descriptor()


@pytest.mark.parametrize("kind", ["pyth", "chainlink"])
def test_runtime_verify_oracle_adapter_families(kind):
    _, oracles = _helpers(); definition, _, evidence = oracles["evidence"](kind)
    result = _runtime(parse_runtime_config(_raw([kind]))).verify(resolver_definition=definition, evidence=evidence, trust_model=oracles["trust"]())
    assert result["result"] == "VERIFIED" and result["verifier"] == _runtime_descriptor()


def test_runtime_verify_rejects_caller_override_and_invalid_bindings():
    adapters, _ = _helpers(); definition, _, evidence = adapters["_zktls_evidence"]()
    config = parse_runtime_config(_raw(["zktls"], zktls={"provider_id": "deterministic-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]}))
    runtime = _runtime(config)
    with pytest.raises(TypeError): runtime.verify(resolver_definition=definition, evidence=evidence, trust_model=adapters["_trust"](), adapter="signed_oracle")
    with pytest.raises(PipelineRejected): runtime.verify(resolver_definition=definition, evidence={**evidence, "definition_hash": H(99)}, trust_model=adapters["_trust"]())
    with pytest.raises(PipelineRejected): runtime.verify(resolver_definition=definition, evidence={"schema": "invalid"}, trust_model=adapters["_trust"]())
    altered = {**definition, "adapter": {**definition["adapter"], "implementation_digest": H(99)}}
    with pytest.raises(PipelineRejected): runtime.verify(resolver_definition=altered, evidence=evidence, trust_model=adapters["_trust"]())


def test_runtime_verify_rejects_disabled_or_missing_dependencies_and_bad_version():
    adapters, _ = _helpers(); definition, _, evidence = adapters["_zktls_evidence"]()
    with pytest.raises(PipelineRejected): _runtime(parse_runtime_config(_raw(["pyth"]))).verify(resolver_definition=definition, evidence=evidence, trust_model=adapters["_trust"]())
    missing_backend = replace(parse_runtime_config(_raw(["zktls"], zktls={"provider_id": "deterministic-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]})), zktls=None)
    with pytest.raises(PipelineRejected): _runtime(missing_backend).verify(resolver_definition=definition, evidence=evidence, trust_model=adapters["_trust"]())
    with pytest.raises(PipelineRejected): _runtime(parse_runtime_config(_raw(["zktls"], zktls={"provider_id": "deterministic-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]}))).verify(resolver_definition=definition, evidence={**evidence, "schema_version": "9.0.0"}, trust_model=adapters["_trust"]())


def test_runtime_verify_backend_failure_is_canonical_rejection_and_identity_is_singleton():
    adapters, _ = _helpers(); definition = adapters["_zktls_definition"]()
    config = parse_runtime_config(_raw(["zktls"], zktls={"provider_id": "deterministic-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]}))
    adapter = _runtime(config).adapter_factory.create(definition)
    acquired = adapter.acquire(definition, ZkTlsMaterial(b"invalid", b'{"schema":"example.response","schema_version":"1","data":{"outcome":"YES"}}', "1", "90", "api.example", H(30), H(31)))
    evidence = normalize_evidence(acquired, definition_hash=adapters["resolver_v2"].resolver_definition_hash(definition).hex(), collector={"implementation": "test"}, transport={"kind": "zktls"}, provenance={"proof_hash": H(8)})
    runtime = _runtime(config)
    result = runtime.verify(resolver_definition=definition, evidence=evidence, trust_model=adapters["_trust"]())
    assert result["result"] == "REJECTED" and result["verifier"] == _runtime_descriptor()
    with pytest.raises(PipelineRejected): ResolverVerifierRuntime(config, runtime.adapter_factory, _runtime_descriptor("prophet.verifier.runtime.b"))


def test_runtime_emits_distinct_signed_attestations_from_trusted_verifier_identity():
    adapters, _ = _helpers(); definition, _, evidence = adapters["_zktls_evidence"]()
    config = parse_runtime_config(_raw(["zktls"], zktls={"provider_id": "deterministic-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]}))
    a_descriptor, b_descriptor = _runtime_descriptor(), {**_runtime_descriptor("prophet.verifier.runtime.b"), "implementation_digest": H(71)}
    a_key, b_key = Keypair.from_seed(bytes(range(32))), Keypair.from_seed(bytes(range(32, 64)))
    a = ResolverVerifierRuntime(config, RuntimeAdapterFactory(runtime_config=config, verifier_descriptors={kind: a_descriptor for kind in ("zktls", "signed_oracle", "pyth", "chainlink")}, clock_ms=lambda: 100), a_descriptor, VerifierAttestationSigner(a_descriptor["adapter_id"], "2.0.0", H(70), a_key), lambda: 100)
    config_b = replace(config, verifier=replace(config.verifier, implementation_id="prophet.verifier.runtime.b"))
    b = ResolverVerifierRuntime(config_b, RuntimeAdapterFactory(runtime_config=config_b, verifier_descriptors={kind: b_descriptor for kind in ("zktls", "signed_oracle", "pyth", "chainlink")}, clock_ms=lambda: 100), b_descriptor, VerifierAttestationSigner(b_descriptor["adapter_id"], "2.0.0", H(71), b_key), lambda: 100)
    context = {"cluster_genesis_hash": H(4), "program_id": "11111111111111111111111111111111", "market": "Stake11111111111111111111111111111111111111", "proof_hash": H(5), "public_inputs_hash": H(6)}
    signed_a = a.verify_attested(resolver_definition=definition, evidence=evidence, trust_model=adapters["_trust"](), attestation_context=context)
    signed_b = b.verify_attested(resolver_definition=definition, evidence=evidence, trust_model=adapters["_trust"](), attestation_context=context)
    assert a_key.pubkey() != b_key.pubkey()
    verify_attestation(signed_a["attestation"], expected_verifier_id=a_descriptor["adapter_id"], expected_verifier_version="2.0.0", expected_verifier_implementation_digest=H(70), expected_public_key=str(a_key.pubkey()))
    verify_attestation(signed_b["attestation"], expected_verifier_id=b_descriptor["adapter_id"], expected_verifier_version="2.0.0", expected_verifier_implementation_digest=H(71), expected_public_key=str(b_key.pubkey()))
    with pytest.raises(Exception): verify_attestation(signed_a["attestation"], expected_verifier_id=b_descriptor["adapter_id"], expected_verifier_version="2.0.0", expected_verifier_implementation_digest=H(71), expected_public_key=str(b_key.pubkey()))


def test_attested_runtime_rejects_expired_result_before_signing_and_requires_production_clock():
    class CountingSigner:
        def __init__(self): self.calls = 0
        def sign(self, payload, *, now_ms):
            self.calls += 1
            raise AssertionError("expired result reached Ed25519 signing")

    class ExpiredRuntime(ResolverVerifierRuntime):
        def verify(self, **kwargs):
            return {
                "schema": "prophet.verification-result.v2", "schema_version": "2.0.0",
                "definition_hash": H(1), "evidence_hash": H(2), "verifier": _runtime_descriptor(),
                "result": "VERIFIED", "checks": [],
                "verified_facts_hex": "7b22636f6e666964656e6365223a2268696768222c226661696c7572655f636f6465223a6e756c6c2c226f7574636f6d65223a22594553222c22737461747573223a225645524946494544222c2276657269666965645f6661637473223a7b7d7d",
                "verified_facts_hash": "35102761430d3fb318a7ce8892e1465d0ef949e14483155b3df52d22c6d63802",
                "observed_at_ms": "100", "valid_from_ms": "100", "valid_until_ms": "200", "finality": None,
            }

    config = parse_runtime_config(_raw(["pyth"], mode="production"))
    factory = RuntimeAdapterFactory(runtime_config=config, verifier_descriptors={"pyth": _runtime_descriptor()}, clock_ms=lambda: 100)
    signer = CountingSigner()
    with pytest.raises(PipelineRejected):
        ExpiredRuntime(config, factory, _runtime_descriptor(), signer)
    runtime = ExpiredRuntime(config, factory, _runtime_descriptor(), signer, lambda: 201)
    context = {"cluster_genesis_hash": H(4), "program_id": "11111111111111111111111111111111", "market": "Stake11111111111111111111111111111111111111", "proof_hash": H(5), "public_inputs_hash": H(6)}
    with pytest.raises(Exception):
        runtime.verify_attested(resolver_definition={}, evidence={}, trust_model={}, attestation_context=context)
    assert signer.calls == 0
