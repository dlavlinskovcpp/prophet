from pathlib import Path
import tempfile
import pytest
from src.runtime_config import RuntimeConfigError, load_runtime_config, parse_runtime_config

def base(): return {"schema_version":1,"environment":"public-devnet","mode":"production","solana":{"cluster":"devnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"a","version":"2"},"allowed_adapters":["pyth","chainlink"],"limits":{"request_max_bytes":1,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"TOKEN"}}

def test_valid_and_deterministic():
    a, b = parse_runtime_config(base()), parse_runtime_config(dict(reversed(list(base().items()))))
    assert a.fingerprint() == b.fingerprint()
    with pytest.raises(Exception): a.environment = "mainnet"

@pytest.mark.parametrize("mutator", [
    lambda x: x.__setitem__("unexpected", True), lambda x: x.__setitem__("schema_version", 9),
    lambda x: x.__setitem__("allowed_adapters", ["pyth","pyth"]), lambda x: x.__setitem__("allowed_adapters", ["nope"]),
    lambda x: x["limits"].__setitem__("request_max_bytes",0), lambda x: x["verifier"].__setitem__("implementation_id",""),
    lambda x: x["solana"].__setitem__("cluster","mainnet"), lambda x: x.__setitem__("environment","mainnet")])
def test_rejects(mutator):
    x=base(); mutator(x)
    with pytest.raises(RuntimeConfigError): parse_runtime_config(x)

def test_templates():
    root=Path(__file__).resolve().parents[3]
    assert load_runtime_config(root/"deploy/operated/localtest/resolver-runtime.test.yaml").environment == "localtest"

def test_signed_oracle_bindings_are_immutable_and_fingerprinted(tmp_path):
    registry=tmp_path/"registry.yaml"; registry.write_text('overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [resolver]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: null\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
    raw=base(); raw["mode"]="test"; raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(registry),"key_bindings":[{"key_id":"id","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
    cfg=parse_runtime_config(raw); assert cfg.signed_oracle and cfg.signed_oracle.key_bindings[0].key_id=="id"
    with pytest.raises(Exception): cfg.signed_oracle.key_bindings += ()
    changed=base(); changed["mode"]="test"; changed["allowed_adapters"]=["signed-oracle"]; changed["signed_oracle"]={"registry_path":str(registry),"key_bindings":[{"key_id":"other","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
    assert cfg.fingerprint()!=parse_runtime_config(changed).fingerprint()

def test_production_runtime_signed_oracle_smoke():
    from src.resolver_v2_adapters import SignedOracleAdapter, SignedOracleMaterial
    from src.signed_oracle_runtime_keys import RegistryBackedOracleKeyring, load_trusted_oracle_key_registry
    from solders.keypair import Keypair
    from prophet_sdk import resolver_v2
    import sys
    adapter_tests = Path(__file__).with_name("test_resolver_v2_adapters.py")
    namespace={}; exec(adapter_tests.read_text(), namespace)
    definition=namespace["_oracle_definition"](); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5)); keypair=Keypair()
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        registry_path=Path(root)/"registry.yaml"; registry_path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "{keypair.pubkey()}"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(registry_path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        config=parse_runtime_config(raw); registry=load_trusted_oracle_key_registry(registry_path)
        adapter=SignedOracleAdapter.from_runtime(runtime_config=config,registry=registry,resolver_definition=definition,verifier_descriptor=descriptor,message_version="2.0.0",clock_ms=lambda:100)
        assert isinstance(adapter.keyring, RegistryBackedOracleKeyring)
        payload=namespace["_oracle_payload"](definition); message=namespace["signed_oracle_message"](payload)
        evidence=namespace["normalize_evidence"](adapter.acquire(definition,SignedOracleMaterial(payload,bytes(keypair.sign_message(message)),"old","1.0.0","100")),definition_hash=resolver_v2.resolver_definition_hash(definition).hex(),collector={"implementation":"test"},transport={"kind":"signed"},provenance={"signature_scheme":"ed25519"})
        assert adapter.verify(definition,evidence,namespace["_trust"]()).status=="VERIFIED"

def test_production_runtime_signed_oracle_key_set_mismatch_smoke():
    from src.resolver_v2_adapters import SignedOracleAdapter, SignedOracleMaterial
    from src.signed_oracle_runtime_keys import load_trusted_oracle_key_registry
    from solders.keypair import Keypair
    from prophet_sdk import resolver_v2
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"](); keypair=Keypair(); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5))
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "{keypair.pubkey()}"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.1","oracle_identity":"oracle"}]}
        adapter=SignedOracleAdapter.from_runtime(runtime_config=parse_runtime_config(raw),registry=load_trusted_oracle_key_registry(path),resolver_definition=definition,verifier_descriptor=descriptor,message_version="2.0.0",clock_ms=lambda:100)
        payload=namespace["_oracle_payload"](definition); message=namespace["signed_oracle_message"](payload)
        evidence=namespace["normalize_evidence"](adapter.acquire(definition,SignedOracleMaterial(payload,bytes(keypair.sign_message(message)),"old","1.0.0","100")),definition_hash=resolver_v2.resolver_definition_hash(definition).hex(),collector={"implementation":"test"},transport={"kind":"signed"},provenance={"signature_scheme":"ed25519"})
        report=adapter.verify(definition,evidence,namespace["_trust"]()); assert report.status=="REJECTED" and report.failure_code=="unknown_oracle_key"

def test_production_runtime_constructor_rejects_signed_oracle_adapter_disabled():
    from src.resolver_v2_adapters import SignedOracleAdapter
    from src.signed_oracle_runtime_keys import load_trusted_oracle_key_registry
    from src.resolver_v2_pipeline import PipelineRejected
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"](); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5))
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["pyth"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        config=parse_runtime_config(raw)
        with pytest.raises(PipelineRejected): SignedOracleAdapter.from_runtime(runtime_config=config,registry=load_trusted_oracle_key_registry(path),resolver_definition=definition,verifier_descriptor=descriptor,message_version="2.0.0")

def test_production_runtime_constructor_rejects_missing_signed_oracle_registry():
    from src.resolver_v2_adapters import SignedOracleAdapter
    from src.resolver_v2_pipeline import PipelineRejected
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"](); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5))
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        with pytest.raises(PipelineRejected): SignedOracleAdapter.from_runtime(runtime_config=parse_runtime_config(raw),registry=None,resolver_definition=definition,verifier_descriptor=descriptor,message_version="2.0.0")

def test_production_runtime_constructor_rejects_missing_signed_oracle_bindings():
    from dataclasses import replace
    from src.resolver_v2_adapters import SignedOracleAdapter
    from src.resolver_v2_pipeline import PipelineRejected
    from src.runtime_config import SignedOracleRuntimeConfig
    from src.signed_oracle_runtime_keys import load_trusted_oracle_key_registry
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"](); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5))
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        validated=parse_runtime_config(raw); assert validated.signed_oracle is not None
        config=replace(validated, signed_oracle=SignedOracleRuntimeConfig(validated.signed_oracle.registry_path, validated.signed_oracle.registry_fingerprint, ()))
        with pytest.raises(PipelineRejected): SignedOracleAdapter.from_runtime(runtime_config=config,registry=load_trusted_oracle_key_registry(path),resolver_definition=definition,verifier_descriptor=descriptor,message_version="2.0.0")

def test_production_runtime_constructor_rejects_missing_resolver_context():
    from src.resolver_v2_adapters import SignedOracleAdapter
    from src.resolver_v2_pipeline import PipelineRejected
    from src.signed_oracle_runtime_keys import load_trusted_oracle_key_registry
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"](); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5))
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        with pytest.raises(PipelineRejected): SignedOracleAdapter.from_runtime(runtime_config=parse_runtime_config(raw),registry=load_trusted_oracle_key_registry(path),resolver_definition=None,verifier_descriptor=descriptor,message_version="2.0.0")

def test_production_runtime_constructor_rejects_missing_message_version():
    from src.resolver_v2_adapters import SignedOracleAdapter
    from src.resolver_v2_pipeline import PipelineRejected
    from src.signed_oracle_runtime_keys import load_trusted_oracle_key_registry
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"](); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5))
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        with pytest.raises(PipelineRejected): SignedOracleAdapter.from_runtime(runtime_config=parse_runtime_config(raw),registry=load_trusted_oracle_key_registry(path),resolver_definition=definition,verifier_descriptor=descriptor,message_version=None)

def test_production_runtime_constructor_rejects_unsupported_message_version():
    from src.resolver_v2_adapters import SignedOracleAdapter
    from src.resolver_v2_pipeline import PipelineRejected
    from src.signed_oracle_runtime_keys import load_trusted_oracle_key_registry
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"](); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5))
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        with pytest.raises(PipelineRejected): SignedOracleAdapter.from_runtime(runtime_config=parse_runtime_config(raw),registry=load_trusted_oracle_key_registry(path),resolver_definition=definition,verifier_descriptor=descriptor,message_version="9.9.9")

def test_production_runtime_constructor_rejects_fixture_signed_oracle_trust():
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"]()
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"fixture-registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "11111111111111111111111111111111"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        with pytest.raises(RuntimeConfigError): parse_runtime_config(raw)

def test_production_runtime_constructor_has_no_legacy_keyring_fallback():
    from src.resolver_v2_adapters import OracleKeyring, SignedOracleAdapter, SignedOracleMaterial
    from src.signed_oracle_runtime_keys import RegistryBackedOracleKeyring, load_trusted_oracle_key_registry
    from solders.keypair import Keypair
    from prophet_sdk import resolver_v2
    namespace={}; exec(Path(__file__).with_name("test_resolver_v2_adapters.py").read_text(), namespace)
    definition=namespace["_oracle_definition"](); descriptor=namespace["_adapter"]("prophet.verifier.signed-oracle", namespace["H"](5)); keypair=Keypair()
    with tempfile.TemporaryDirectory(prefix="prophet-runtime-") as root:
        path=Path(root)/"registry.yaml"; path.write_text(f'overlap_ms: 0\nrecords:\n- oracle_identity: oracle\n  resolver_ids: [{definition["resolver_id"]}]\n  public_key: "{keypair.pubkey()}"\n  key_epoch: epoch\n  activation_time_ms: "0"\n  retirement_time_ms: "1000"\n  allowed_message_versions: ["2.0.0"]\n  status: active\n')
        raw=base(); raw["allowed_adapters"]=["signed-oracle"]; raw["signed_oracle"]={"registry_path":str(path),"key_bindings":[{"key_id":"old","key_set_version":"1.0.0","oracle_identity":"oracle"}]}
        registry=load_trusted_oracle_key_registry(path)
        adapter=SignedOracleAdapter.from_runtime(runtime_config=parse_runtime_config(raw),registry=registry,resolver_definition=definition,verifier_descriptor=descriptor,message_version="2.0.0",clock_ms=lambda:100)
        assert isinstance(adapter.keyring, RegistryBackedOracleKeyring) and not isinstance(adapter.keyring, OracleKeyring)
        raw["signed_oracle"]["key_bindings"][0]["key_id"]="unbound"
        no_fallback=SignedOracleAdapter.from_runtime(runtime_config=parse_runtime_config(raw),registry=registry,resolver_definition=definition,verifier_descriptor=descriptor,message_version="2.0.0",clock_ms=lambda:100)
        payload=namespace["_oracle_payload"](definition); message=namespace["signed_oracle_message"](payload)
        evidence=namespace["normalize_evidence"](no_fallback.acquire(definition,SignedOracleMaterial(payload,bytes(keypair.sign_message(message)),"old","1.0.0","100")),definition_hash=resolver_v2.resolver_definition_hash(definition).hex(),collector={"implementation":"test"},transport={"kind":"signed"},provenance={"signature_scheme":"ed25519"})
        report=no_fallback.verify(definition,evidence,namespace["_trust"]()); assert report.status=="REJECTED" and report.failure_code=="unknown_oracle_key"
