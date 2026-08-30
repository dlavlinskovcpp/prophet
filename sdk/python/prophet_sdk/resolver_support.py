"""Public resolver support classification used by SDK/operator tooling."""
from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Mapping

from . import resolver_v2


class ResolverSupport(str, Enum):
    OPERATED_SUPPORTED = "OPERATED_SUPPORTED"
    EXTERNAL_UNVERIFIED = "EXTERNAL_UNVERIFIED"
    UNSUPPORTED = "UNSUPPORTED"


def classify_resolver_support(
    resolver_hash: bytes,
    definition: Mapping[str, Any] | None,
    *,
    enabled_resolver_types: Iterable[str],
    verifier_implementations: Mapping[str, Any],
) -> ResolverSupport:
    """Never classify an unknown permissionless resolver as operated-supported."""
    if not isinstance(resolver_hash, bytes) or len(resolver_hash) != 32 or resolver_hash == bytes(32):
        return ResolverSupport.UNSUPPORTED
    if definition is None:
        return ResolverSupport.EXTERNAL_UNVERIFIED
    try:
        canonical = resolver_v2.validate_resolver_definition(definition)
        if resolver_v2.resolver_definition_hash(canonical) != resolver_hash:
            return ResolverSupport.UNSUPPORTED
        if canonical["resolver_type"] not in set(enabled_resolver_types):
            return ResolverSupport.UNSUPPORTED
        if not verifier_implementations.get(canonical["resolver_type"]):
            return ResolverSupport.UNSUPPORTED
    except Exception:
        return ResolverSupport.UNSUPPORTED
    return ResolverSupport.OPERATED_SUPPORTED
