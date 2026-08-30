"""Strict public metadata binding for one real localtest chain instance."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from solders.pubkey import Pubkey


CHAIN_BINDING_SCHEMA = "PROPHET_LOCALTEST_CHAIN_BINDING_V1"
_FIELDS = frozenset({
    "schema", "version", "cluster_classification", "genesis_hash", "program_id",
    "signer_a_public_key", "signer_b_public_key", "notary_config", "notary_config_version",
    "threshold", "market", "creator", "market_nonce", "resolver_definition_hash",
    "open_ts", "lock_ts", "resolve_ts", "outcome", "evidence_hash", "proof_hash",
    "public_inputs_hash", "finalized_bootstrap_slot", "finalized_bootstrap_block_time",
    "finalized_account_context_slot",
})
_HEX = frozenset({"genesis_hash", "resolver_definition_hash", "evidence_hash", "proof_hash", "public_inputs_hash"})
_KEYS = frozenset({"program_id", "signer_a_public_key", "signer_b_public_key", "notary_config", "market", "creator"})
_INTS = frozenset({"version", "notary_config_version", "threshold", "market_nonce", "open_ts", "lock_ts", "resolve_ts", "finalized_bootstrap_slot", "finalized_bootstrap_block_time", "finalized_account_context_slot"})


class LocaltestChainBindingError(ValueError):
    pass


def _int(value: Any, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise LocaltestChainBindingError(f"{name}_invalid")
    return value


@dataclass(frozen=True)
class LocaltestChainBindingV1:
    values: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> "LocaltestChainBindingV1":
        if not isinstance(value, Mapping) or frozenset(value) != _FIELDS:
            raise LocaltestChainBindingError("chain_binding_shape_invalid")
        if value["schema"] != CHAIN_BINDING_SCHEMA or value["version"] != 1 or value["cluster_classification"] != "FUNCTIONAL_TEST_ONLY":
            raise LocaltestChainBindingError("chain_binding_schema_invalid")
        for name in _HEX:
            if not isinstance(value[name], str) or len(value[name]) != 64 or any(c not in "0123456789abcdef" for c in value[name]):
                raise LocaltestChainBindingError(f"{name}_invalid")
        for name in _KEYS:
            try:
                if not isinstance(value[name], str) or str(Pubkey.from_string(value[name])) != value[name]:
                    raise ValueError
            except Exception as exc:
                raise LocaltestChainBindingError(f"{name}_invalid") from exc
        for name in _INTS:
            _int(value[name], name)
        if value["notary_config_version"] != 1 or value["threshold"] != 2 or value["market_nonce"] >= 1 << 64:
            raise LocaltestChainBindingError("chain_binding_protocol_values_invalid")
        if value["signer_a_public_key"] == value["signer_b_public_key"]:
            raise LocaltestChainBindingError("chain_binding_signer_identity_collision")
        if not value["open_ts"] <= value["lock_ts"] <= value["resolve_ts"]:
            raise LocaltestChainBindingError("chain_binding_time_range_invalid")
        if value["outcome"] not in {"YES", "NO", "INVALID"}:
            raise LocaltestChainBindingError("chain_binding_outcome_invalid")
        return cls(dict(value))

    def as_mapping(self) -> dict[str, Any]:
        return dict(self.values)

    def __getitem__(self, name: str) -> Any:
        return self.values[name]
