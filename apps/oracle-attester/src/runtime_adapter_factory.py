"""Deterministic construction of approved Resolver V2 adapters only."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Optional

from .resolver_v2_adapters import SequenceReplayGuard, SignedOracleAdapter, ZkTlsAdapter
from .resolver_v2_oracle_adapters import ChainlinkAdapter, PythAdapter
from .resolver_v2_pipeline import PipelineRejected

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


@dataclass(frozen=True)
class RuntimeAdapterDescriptor:
    resolver_type: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str
    runtime_implementation_id: str
    required_dependencies: tuple[str, ...]


def _digest(byte: int) -> str:
    return f"{byte:02x}" * 32


DEFAULT_RUNTIME_ADAPTERS = (
    RuntimeAdapterDescriptor("zktls", "prophet.resolver.zktls", "2.0.0", _digest(1), "prophet.runtime.zktls.v1", ("zktls_proof_verifier",)),
    RuntimeAdapterDescriptor("signed_oracle", "prophet.resolver.signed-oracle", "2.0.0", _digest(4), "prophet.runtime.signed-oracle.v1", ("signed_oracle_registry", "legacy_key_bindings")),
    RuntimeAdapterDescriptor("pyth", "prophet.resolver.pyth", "2.0.0", _digest(3), "prophet.runtime.pyth.v1", ()),
    RuntimeAdapterDescriptor("chainlink", "prophet.resolver.chainlink", "2.0.0", _digest(3), "prophet.runtime.chainlink.v1", ()),
)
_RUNTIME_ALLOWLIST_NAME = {"signed_oracle": "signed-oracle"}


class RuntimeAdapterRegistry:
    """Immutable allowlist keyed by the complete canonical adapter identity."""

    __slots__ = ("_by_identity", "_sealed")

    def __init__(self, descriptors: Iterable[RuntimeAdapterDescriptor] = DEFAULT_RUNTIME_ADAPTERS):
        rows = tuple(descriptors)
        by_identity = {(row.resolver_type, row.adapter_id, row.adapter_version, row.adapter_digest): row for row in rows}
        if not rows or len(rows) != len(by_identity):
            raise PipelineRejected("runtime_adapter_registry_ambiguous")
        object.__setattr__(self, "_by_identity", MappingProxyType(by_identity))
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("runtime adapter registry is immutable")
        object.__setattr__(self, name, value)

    def resolve(self, definition: Mapping[str, Any]) -> RuntimeAdapterDescriptor:
        try:
            resolver_v2.validate_resolver_definition(definition)
            adapter = definition["adapter"]
            key = (definition["resolver_type"], adapter["adapter_id"], adapter["adapter_version"], adapter["implementation_digest"])
        except (KeyError, resolver_v2.ResolverV2Error) as exc:
            raise PipelineRejected("runtime_adapter_definition_invalid") from exc
        descriptor = self._by_identity.get(key)
        if descriptor is None:
            raise PipelineRejected("runtime_adapter_identity_unapproved")
        return descriptor


class RuntimeAdapterFactory:
    """Trusted startup wiring; selection always derives from canonical metadata."""

    def __init__(self, *, runtime_config: Any, verifier_descriptors: Mapping[str, Mapping[str, Any]], signed_oracle_registry: Any = None, registry: Optional[RuntimeAdapterRegistry] = None, clock_ms: Optional[Callable[[], int]] = None, metrics: Any = None, signed_oracle_replay_guard: Optional[SequenceReplayGuard] = None):
        if getattr(runtime_config, "mode", None) == "production" and clock_ms is None:
            raise PipelineRejected("runtime_adapter_clock_required")
        if clock_ms is not None and not callable(clock_ms):
            raise PipelineRejected("runtime_adapter_clock_invalid")
        self.runtime_config = runtime_config
        self._verifier_descriptors = MappingProxyType(dict(verifier_descriptors))
        self.signed_oracle_registry = signed_oracle_registry
        self.registry = registry or RuntimeAdapterRegistry()
        self.clock_ms, self.metrics = clock_ms, metrics
        self._signed_oracle_replay_guard = signed_oracle_replay_guard or SequenceReplayGuard()

    def create(self, resolver_definition: Mapping[str, Any]):
        descriptor = self.registry.resolve(resolver_definition)
        allowlist_name = _RUNTIME_ALLOWLIST_NAME.get(descriptor.resolver_type, descriptor.resolver_type)
        if allowlist_name not in getattr(self.runtime_config, "allowed_adapters", ()):
            raise PipelineRejected("runtime_adapter_not_enabled")
        verifier_descriptor = self._verifier_descriptors.get(descriptor.resolver_type)
        if verifier_descriptor is None:
            raise PipelineRejected("runtime_adapter_dependency_missing")
        if descriptor.resolver_type == "zktls":
            return ZkTlsAdapter.from_runtime(runtime_config=self.runtime_config, resolver_definition=resolver_definition, verifier_descriptor=verifier_descriptor, clock_ms=self.clock_ms)
        if descriptor.resolver_type == "signed_oracle":
            source = resolver_definition.get("source", {})
            return SignedOracleAdapter.from_runtime(runtime_config=self.runtime_config, registry=self.signed_oracle_registry, resolver_definition=resolver_definition, verifier_descriptor=verifier_descriptor, message_version=source.get("payload_schema_version"), replay_guard=self._signed_oracle_replay_guard, clock_ms=self.clock_ms)
        if descriptor.resolver_type == "pyth":
            return PythAdapter(adapter_digest=descriptor.adapter_digest, verifier_descriptor=verifier_descriptor, clock_ms=self.clock_ms, metrics=self.metrics)
        if descriptor.resolver_type == "chainlink":
            return ChainlinkAdapter(adapter_digest=descriptor.adapter_digest, verifier_descriptor=verifier_descriptor, clock_ms=self.clock_ms, metrics=self.metrics)
        raise PipelineRejected("runtime_adapter_implementation_unavailable")
