import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "sdk/python/prophet_sdk/resolver_v2.py"
SPEC = importlib.util.spec_from_file_location("prophet_resolver_v2_test", MODULE_PATH)
resolver_v2 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = resolver_v2
SPEC.loader.exec_module(resolver_v2)
VECTOR = json.loads((ROOT / "resolver-v2/test-vectors/v2.json").read_text(encoding="utf-8"))


def test_permanent_cross_language_vectors_match():
    bundle = VECTOR["bundle_payload"]
    hashes = VECTOR["hashes"]
    assert resolver_v2.adapter_digest(bundle["verifier"]).hex() == hashes["adapter"]
    assert resolver_v2.trust_model_digest(bundle["trust_model"]).hex() == hashes["trust_model"]
    assert resolver_v2.resolver_definition_hash(bundle["resolver_definition"]).hex() == hashes["definition"]
    assert [resolver_v2.evidence_hash(item).hex() for item in bundle["evidence"]] == hashes["evidence"]
    assert [resolver_v2.verification_result_hash(item).hex() for item in bundle["verification_results"]] == hashes["verification"]
    assert resolver_v2.resolution_bundle_hash(bundle).hex() == hashes["bundle"]
    resolver_v2.validate_resolution_bundle(bundle, now_ms=2000)


def test_canonicalization_and_malformed_rejection():
    definition = VECTOR["bundle_payload"]["resolver_definition"]
    reordered = {key: definition[key] for key in reversed(list(definition.keys()))}
    assert resolver_v2.resolver_definition_hash(reordered) == resolver_v2.resolver_definition_hash(definition)
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.parse_canonical_json(b'{ "schema":"x" }')
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.canonical_json_bytes({"number": 1})
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.canonical_json_bytes({"text": "Cafe\u0301"})


def test_bundle_validation_rejects_replay_binding_staleness_and_duplicates():
    duplicate = copy.deepcopy(VECTOR["bundle_payload"])
    duplicate["evidence"][1]["evidence_id"] = duplicate["evidence"][0]["evidence_id"]
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.validate_resolution_bundle(duplicate)

    stale = copy.deepcopy(VECTOR["bundle_payload"])
    stale["valid_until_ms"] = "1999"
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.validate_resolution_bundle(stale, now_ms=2000)

    mismatch = copy.deepcopy(VECTOR["bundle_payload"])
    mismatch["evidence"][0]["definition_hash"] = "00" * 32
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.validate_resolution_bundle(mismatch)

    conflicting = copy.deepcopy(VECTOR["bundle_payload"])
    conflicting["verification_results"][0]["valid_until_ms"] = "1999"
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.validate_resolution_bundle(conflicting)

    unsupported = copy.deepcopy(VECTOR["bundle_payload"])
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.validate_resolution_bundle(unsupported, supported_adapter_versions={"prophet.resolver.zktls": ("9.9.9",)})


def test_legacy_hash_is_unchanged_and_domain_separated():
    legacy = {"method": "GET", "path": "data.price", "predicate": "gt", "target_value": 3, "url": "https://example.test"}
    legacy_bytes = json.dumps(legacy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(legacy_bytes).hexdigest() == "0931d263a14d80c3a5d48abf5bb808cf6bf19547a6db1de8474ac40db84226c6"
    v2 = resolver_v2.resolver_definition_hash(VECTOR["bundle_payload"]["resolver_definition"]).hex()
    assert v2 != hashlib.sha256(resolver_v2.canonical_json_bytes(VECTOR["bundle_payload"]["resolver_definition"])).hexdigest()
    bundle = VECTOR["bundle_payload"]
    assert resolver_v2.resolution_bundle_hash(bundle).hex() != hashlib.sha256(resolver_v2.canonical_json_bytes(bundle)).hexdigest()


def test_immutable_registry_preserves_entry_and_writes_separate_deprecation_record():
    bundle = VECTOR["bundle_payload"]
    entry = resolver_v2.RegistryEntryV2(
        resolver_id="btc-usd-nfc",
        resolver_definition_hash=VECTOR["hashes"]["definition"],
        adapter_digest=VECTOR["hashes"]["adapter"],
        trust_model_digest=VECTOR["hashes"]["trust_model"],
        schema_version="2.0.0",
        created_at_ms="0",
    )
    registry = resolver_v2.ImmutableResolverRegistryV2()
    registry.create(entry)
    before = entry.digest()
    deprecation = registry.deprecate("btc-usd-nfc", "1", "adapter superseded", "btc-usd-nfc-v2")
    assert registry.get("btc-usd-nfc").digest() == before
    assert deprecation["entry_digest"] == before.hex()
    with pytest.raises(resolver_v2.ResolverV2Error):
        registry.create(entry)
    with pytest.raises(resolver_v2.ResolverV2Error):
        resolver_v2.RegistryEntryV2(**{**entry.__dict__, "schema_version": "9.0.0"}).payload()
