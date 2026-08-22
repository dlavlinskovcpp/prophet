from dataclasses import replace
from pathlib import Path
import tempfile

import pytest

from src.resolver_v2_adapters import SignedOracleAdapter, ZkTlsAdapter
from src.resolver_v2_oracle_adapters import ChainlinkAdapter, PythAdapter
from src.resolver_v2_pipeline import PipelineRejected
from src.runtime_adapter_factory import RuntimeAdapterDescriptor, RuntimeAdapterFactory, RuntimeAdapterRegistry
from src.runtime_config import SignedOracleRuntimeConfig, parse_runtime_config
from src.signed_oracle_runtime_keys import RegistryBackedOracleKeyring, load_trusted_oracle_key_registry


H = lambda byte: f"{byte:02x}" * 32


def _raw(allowed, *, zktls=None, signed_oracle=None, mode="test"):
    raw = {"schema_version": 1, "environment": "public-devnet", "mode": mode, "solana": {"cluster": "devnet", "genesis_hash": "g", "prophet_program_id": "p"}, "resolver_v2": {"schema_version": 2}, "verifier": {"implementation_id": "runtime", "version": "2"}, "allowed_adapters": allowed, "limits": {"request_max_bytes": 1, "request_timeout_seconds": 1}, "freshness": {"default_max_evidence_age_seconds": 1, "default_max_verification_age_seconds": 1}, "internal_auth": {"token_env": "TOKEN"}}
    if zktls is not None: raw["zktls"] = zktls
    if signed_oracle is not None: raw["signed_oracle"] = signed_oracle
    return raw


def _zktls_runtime():
    return parse_runtime_config(_raw(["zktls"], zktls={"provider_id": "deterministic-provider", "verifier_backend": "deterministic-test", "allowed_proof_versions": ["1"]}))


def _helpers():
    adapters, oracles = {}, {}
    exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), adapters)
    exec(Path(__file__).with_name("test_resolver_v2_oracle_adapters.py").read_text(), oracles)
    return adapters, oracles


def _factory(config, *, signed_registry=None):
    adapters, oracles = _helpers()
    descriptors = {"zktls": adapters["_adapter"]("prophet.verifier.zktls", H(3)), "signed_oracle": adapters["_adapter"]("prophet.verifier.signed-oracle", H(5)), "pyth": oracles["descriptor"]("prophet.verifier.pyth.primary", 4), "chainlink": oracles["descriptor"]("prophet.verifier.chainlink.primary", 4)}
    return RuntimeAdapterFactory(runtime_config=config, verifier_descriptors=descriptors, signed_oracle_registry=signed_registry, clock_ms=lambda: 100)


def test_runtime_factory_constructs_exact_existing_adapter_families():
    adapters, oracles = _helpers()
    zktls = _factory(_zktls_runtime()).create(adapters["_zktls_definition"]())
    pyth = _factory(parse_runtime_config(_raw(["pyth"]))).create(oracles["definition"]("pyth"))
    chainlink = _factory(parse_runtime_config(_raw(["chainlink"]))).create(oracles["definition"]("chainlink"))
    assert isinstance(zktls, ZkTlsAdapter) and zktls.proof_verifier.backend_id == "deterministic-test"
    assert isinstance(pyth, PythAdapter) and isinstance(chainlink, ChainlinkAdapter)


def test_runtime_factory_constructs_signed_oracle_with_registry_backed_keyring():
    adapters, _ = _helpers(); definition = adapters["_oracle_definition"]()
    with tempfile.TemporaryDirectory(prefix="prophet-factory-") as root:
        path = Path(root) / "registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        config = parse_runtime_config(_raw(["signed-oracle"], mode="production", signed_oracle={"registry_path": str(path), "key_bindings": [{"key_id": "old", "key_set_version": "1.0.0", "oracle_identity": "oracle"}]}))
        adapter = _factory(config, signed_registry=load_trusted_oracle_key_registry(path)).create(definition)
        assert isinstance(adapter, SignedOracleAdapter) and isinstance(adapter.keyring, RegistryBackedOracleKeyring)


@pytest.mark.parametrize("mutation", [lambda d: d.update({"resolver_type": "unknown"}), lambda d: d["adapter"].update({"adapter_version": "9.9.9"}), lambda d: d["adapter"].update({"implementation_digest": H(99)})])
def test_runtime_factory_rejects_unapproved_canonical_identity(mutation):
    adapters, _ = _helpers(); definition = adapters["_zktls_definition"](); mutation(definition)
    with pytest.raises(PipelineRejected): _factory(_zktls_runtime()).create(definition)


def test_runtime_factory_enforces_allowlist_and_has_no_caller_override():
    adapters, _ = _helpers(); definition = adapters["_zktls_definition"](); factory = _factory(parse_runtime_config(_raw(["pyth"])))
    with pytest.raises(PipelineRejected): factory.create(definition)
    with pytest.raises(TypeError): factory.create(definition, adapter="signed_oracle")


def test_runtime_factory_rejects_missing_zktls_and_signed_oracle_dependencies():
    adapters, _ = _helpers(); zktls_definition, oracle_definition = adapters["_zktls_definition"](), adapters["_oracle_definition"]()
    missing_backend = replace(_zktls_runtime(), zktls=None)
    with pytest.raises(PipelineRejected): _factory(missing_backend).create(zktls_definition)
    with tempfile.TemporaryDirectory(prefix="prophet-factory-") as root:
        path = Path(root) / "registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{oracle_definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        config = parse_runtime_config(_raw(["signed-oracle"], mode="production", signed_oracle={"registry_path": str(path), "key_bindings": [{"key_id": "old", "key_set_version": "1.0.0", "oracle_identity": "oracle"}]}))
        with pytest.raises(PipelineRejected): _factory(config).create(oracle_definition)
        assert config.signed_oracle is not None
        no_bindings = replace(config, signed_oracle=SignedOracleRuntimeConfig(config.signed_oracle.registry_path, config.signed_oracle.registry_fingerprint, ()))
        with pytest.raises(PipelineRejected): _factory(no_bindings, signed_registry=load_trusted_oracle_key_registry(path)).create(oracle_definition)


def test_runtime_adapter_registry_is_immutable_and_rejects_duplicate_registration():
    descriptor = RuntimeAdapterDescriptor("zktls", "prophet.resolver.zktls", "2.0.0", H(1), "test", ())
    with pytest.raises(PipelineRejected): RuntimeAdapterRegistry((descriptor, descriptor))
    registry = RuntimeAdapterRegistry()
    with pytest.raises(TypeError): registry._by_identity["x"] = descriptor
    with pytest.raises(AttributeError): registry._by_identity = {}


def test_production_runtime_factory_requires_explicit_clock():
    config = parse_runtime_config(_raw(["pyth"], mode="production"))
    with pytest.raises(PipelineRejected, match="runtime_adapter_clock_required"):
        RuntimeAdapterFactory(runtime_config=config, verifier_descriptors={})
