from copy import deepcopy

import pytest

from prophet_sdk import resolver_v2
from src.resolver_support import ResolverSupport, ResolverSupportError, classify_resolver, preflight_operated_resolver
from tests.test_resolver_v2_adapters import _zktls_definition


def _definition():
    return _zktls_definition()


def _hash(definition):
    return resolver_v2.resolver_definition_hash(definition)


def _kwargs():
    return {
        "enabled_resolver_types": ("zktls",),
        "verifier_implementations": {"zktls": object()},
    }


def test_operated_support_requires_exact_v2_definition_and_runtime_identity():
    definition = _definition()
    result = classify_resolver(_hash(definition), definition, **_kwargs())
    assert result.classification is ResolverSupport.OPERATED_SUPPORTED

    changed = deepcopy(definition)
    changed["source"]["provider"] = "different"
    assert classify_resolver(_hash(definition), changed, **_kwargs()).classification is ResolverSupport.UNSUPPORTED


@pytest.mark.parametrize("value", [None, bytes(32)])
def test_unknown_or_zero_resolver_is_not_operated_supported(value):
    result = classify_resolver(value, None, **_kwargs()) if value is not None else classify_resolver(b"x" * 32, None, **_kwargs())
    expected = ResolverSupport.UNSUPPORTED if value == bytes(32) else ResolverSupport.EXTERNAL_UNVERIFIED
    assert result.classification is expected


def test_preflight_fails_closed_for_missing_definition_and_missing_verifier():
    definition = _definition()
    with pytest.raises(ResolverSupportError, match="resolver_definition_missing"):
        preflight_operated_resolver(_hash(definition), load_definition=lambda _hash: (_ for _ in ()).throw(FileNotFoundError()), **_kwargs())
    with pytest.raises(ResolverSupportError, match="verifier_implementation_unavailable"):
        preflight_operated_resolver(_hash(definition), load_definition=lambda _hash: definition, enabled_resolver_types=("zktls",), verifier_implementations={})
