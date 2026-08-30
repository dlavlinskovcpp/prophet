"""Fail-closed classification and preflight for operated Resolver V2 markets."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:  # pragma: no cover - source-tree fallback
    from .resolver_v2_pipeline import resolver_v2

from .runtime_adapter_factory import RuntimeAdapterRegistry


class ResolverSupport(str, Enum):
    OPERATED_SUPPORTED = "OPERATED_SUPPORTED"
    EXTERNAL_UNVERIFIED = "EXTERNAL_UNVERIFIED"
    UNSUPPORTED = "UNSUPPORTED"


class ResolverSupportError(ValueError):
    """A resolver cannot be admitted to an operated market-creation route."""


@dataclass(frozen=True)
class ResolverSupportResult:
    classification: ResolverSupport
    reason: str
    definition: Mapping[str, Any] | None = None


def classify_resolver(
    resolver_hash: bytes,
    definition: Mapping[str, Any] | None,
    *,
    enabled_resolver_types: Iterable[str],
    verifier_implementations: Mapping[str, Any],
    registry: RuntimeAdapterRegistry | None = None,
) -> ResolverSupportResult:
    """Classify a market without claiming that unknown external resolvers are safe."""
    if not isinstance(resolver_hash, bytes) or len(resolver_hash) != 32:
        return ResolverSupportResult(ResolverSupport.UNSUPPORTED, "resolver_hash_invalid")
    if resolver_hash == bytes(32):
        return ResolverSupportResult(ResolverSupport.UNSUPPORTED, "resolver_hash_zero")
    if definition is None:
        return ResolverSupportResult(ResolverSupport.EXTERNAL_UNVERIFIED, "definition_not_available")
    try:
        canonical = resolver_v2.validate_resolver_definition(definition)
        if resolver_v2.resolver_definition_hash(canonical) != resolver_hash:
            return ResolverSupportResult(ResolverSupport.UNSUPPORTED, "resolver_hash_mismatch")
        resolver_type = canonical["resolver_type"]
        if resolver_type not in set(enabled_resolver_types):
            return ResolverSupportResult(ResolverSupport.UNSUPPORTED, "resolver_type_not_enabled", canonical)
        (registry or RuntimeAdapterRegistry()).resolve(canonical)
        if not verifier_implementations.get(resolver_type):
            return ResolverSupportResult(ResolverSupport.UNSUPPORTED, "verifier_implementation_unavailable", canonical)
    except Exception:
        return ResolverSupportResult(ResolverSupport.UNSUPPORTED, "resolver_definition_unsupported", definition)
    return ResolverSupportResult(ResolverSupport.OPERATED_SUPPORTED, "approved_v2_runtime", canonical)


def preflight_operated_resolver(
    resolver_hash: bytes,
    *,
    load_definition: Callable[[bytes], Mapping[str, Any]],
    enabled_resolver_types: Iterable[str],
    verifier_implementations: Mapping[str, Any],
    registry: RuntimeAdapterRegistry | None = None,
) -> Mapping[str, Any]:
    """Load and validate the exact V2 definition before a market transaction."""
    if resolver_hash == bytes(32):
        raise ResolverSupportError("resolver_hash_zero")
    try:
        definition = load_definition(resolver_hash)
    except Exception as exc:
        raise ResolverSupportError("resolver_definition_missing") from exc
    result = classify_resolver(
        resolver_hash,
        definition,
        enabled_resolver_types=enabled_resolver_types,
        verifier_implementations=verifier_implementations,
        registry=registry,
    )
    if result.classification is not ResolverSupport.OPERATED_SUPPORTED:
        raise ResolverSupportError(result.reason)
    return dict(result.definition or {})
