"""Fail-closed retirement guard for the former dual-token runtime schema."""
from __future__ import annotations

from typing import Any, Mapping


class SecureSettlementRuntimeError(ValueError):
    pass


_RETIRED_FIELDS = frozenset(("signer_a_vault_token_env", "signer_b_vault_token_env"))


def reject_legacy_secure_settlement_config(value: Any) -> None:
    """Reject every retired secure-settlement artifact without reading secrets."""
    if isinstance(value, Mapping):
        policy = value.get("secure_settlement", value)
        if isinstance(policy, Mapping) and _RETIRED_FIELDS & set(policy):
            raise SecureSettlementRuntimeError("legacy_dual_token_config_retired")
    raise SecureSettlementRuntimeError("legacy_secure_settlement_runtime_retired")


def load_secure_settlement_runtime(*_: Any, **__: Any) -> None:
    reject_legacy_secure_settlement_config({})


def load_secure_auth_tokens(*_: Any, **__: Any) -> None:
    reject_legacy_secure_settlement_config({})
