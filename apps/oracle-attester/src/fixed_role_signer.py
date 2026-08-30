"""Fixed-role startup guards for the independent signer service.

The role is selected by this module's executable identity, before a caller can
obtain a Vault credential or construct an execution engine.  The shared
P0C3A/P0C3B implementation remains the sole signer implementation.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from .independent_signer_runtime import IndependentSignerServiceConfig


class FixedRoleSignerStartupError(RuntimeError):
    """Raised when a process attempts to cross its fixed signer boundary."""


def load_fixed_role_config(role: str, value: Any) -> IndependentSignerServiceConfig:
    """Parse one role-local config before any credential lookup occurs."""
    if role not in {"A", "B"}:
        raise FixedRoleSignerStartupError("fixed_signer_role_invalid")
    config = IndependentSignerServiceConfig.from_mapping(value)
    if config.signer_role != role:
        raise FixedRoleSignerStartupError("fixed_signer_role_override_rejected")
    return config


def fixed_role_child_environment(config: IndependentSignerServiceConfig) -> dict[str, str]:
    """Return the only environment a signer command child may receive.

    Ambient parent values, including the peer's Vault/admission/RPC values, are
    intentionally excluded.  Values are copied only after the immutable role
    and role-local config have been validated.
    """
    if not isinstance(config, IndependentSignerServiceConfig):
        raise FixedRoleSignerStartupError("fixed_signer_config_required")
    peer_marker = "SIGNER_B_" if config.signer_role == "A" else "SIGNER_A_"
    names = ("PATH", "LANG", "LC_ALL", config.vault_token_env, config.admission_token_env, config.rpc_url_env)
    result = {name: os.environ[name] for name in names if name in os.environ}
    if any(peer_marker in name.upper() for name in result):
        raise FixedRoleSignerStartupError("fixed_signer_peer_environment_rejected")
    return result
