from copy import deepcopy

from prophet_sdk import ResolverSupport, classify_resolver_support, resolver_v2


def _definition():
    return {
        "schema": resolver_v2.SCHEMAS["definition"],
        "schema_version": resolver_v2.VERSION,
        "resolver_id": "demo.resolver",
        "resolver_type": "pyth",
        "adapter": {
            "schema": resolver_v2.SCHEMAS["adapter"],
            "schema_version": resolver_v2.VERSION,
            "adapter_id": "prophet.resolver.pyth",
            "adapter_version": resolver_v2.VERSION,
            "implementation_digest": "03" * 32,
        },
        "trust_model": {
            "schema": resolver_v2.SCHEMAS["trust_model"],
            "schema_version": resolver_v2.VERSION,
            "trust_model_id": "demo.trust",
            "trust_model_version": resolver_v2.VERSION,
            "document_hash": "05" * 32,
        },
        "source": {"feed": "demo"},
        "verification_policy": {"finality": "finalized"},
        "evaluation": {"predicate": "equals"},
        "timing": {"not_before_ms": "0", "observation_deadline_ms": "1", "max_evidence_age_ms": "1"},
        "conflict_policy": {"mode": "reject"},
        "fallback_policy": {"mode": "reject"},
    }


def test_sdk_does_not_equate_permissionless_with_operated_support():
    definition = _definition()
    resolver_hash = resolver_v2.resolver_definition_hash(definition)
    assert classify_resolver_support(resolver_hash, definition, enabled_resolver_types=("pyth",), verifier_implementations={"pyth": True}) is ResolverSupport.OPERATED_SUPPORTED
    assert classify_resolver_support(b"x" * 32, None, enabled_resolver_types=("pyth",), verifier_implementations={}) is ResolverSupport.EXTERNAL_UNVERIFIED
    changed = deepcopy(definition)
    changed["adapter"]["implementation_digest"] = "09" * 32
    assert classify_resolver_support(resolver_hash, changed, enabled_resolver_types=("pyth",), verifier_implementations={"pyth": True}) is ResolverSupport.UNSUPPORTED
