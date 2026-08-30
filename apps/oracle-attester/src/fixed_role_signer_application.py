"""Role-fixed assembly for one independent signer ASGI application.

The role is a module-owned constant at each public entrypoint.  This helper
does not accept a request, environment, or command-line role selector.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from fastapi import FastAPI

from .fixed_role_signer import FixedRoleSignerStartupError, load_fixed_role_config
from .independent_signer_execution import IndependentSignerEngine
from .independent_signer_runtime import IndependentSignerServiceConfig
from .independent_signer_service import create_independent_signer_service
from .signer_admission_runtime import SignerAdmissionRuntime


class FixedRoleSignerApplicationStartupError(RuntimeError):
    """A role-local standalone signer application cannot be safely assembled."""


def _reject_peer_environment(role: str) -> None:
    peer = "SIGNER_B_" if role == "A" else "SIGNER_A_"
    if any(name.upper().startswith(peer) for name in os.environ):
        raise FixedRoleSignerApplicationStartupError("fixed_signer_peer_environment_rejected")


def create_fixed_role_signer_application(
    *,
    fixed_role: str,
    config_value: Mapping[str, Any],
    admission_factory: Callable[[IndependentSignerServiceConfig], SignerAdmissionRuntime],
    engine_factory: Callable[[IndependentSignerServiceConfig], IndependentSignerEngine],
    clock: Callable[[], Any] | None = None,
) -> FastAPI:
    """Build exactly one role-local G3 -> P0C1 -> P0C2 signer application.

    Factories are deliberately called only after the fixed role and its public
    configuration have been validated.  ``engine_factory`` is invoked exactly
    once and is the only place a role-local signing capability may be acquired.
    """
    if fixed_role not in {"A", "B"}:
        raise FixedRoleSignerApplicationStartupError("fixed_signer_role_invalid")
    try:
        config = load_fixed_role_config(fixed_role, config_value)
    except FixedRoleSignerStartupError:
        raise
    except Exception as exc:
        raise FixedRoleSignerApplicationStartupError("fixed_signer_config_invalid") from exc
    _reject_peer_environment(fixed_role)
    if not callable(admission_factory) or not callable(engine_factory):
        raise FixedRoleSignerApplicationStartupError("fixed_signer_factories_required")
    try:
        admission = admission_factory(config)
    except Exception as exc:
        raise FixedRoleSignerApplicationStartupError("fixed_signer_admission_startup_failed") from exc
    if not isinstance(admission, SignerAdmissionRuntime):
        raise FixedRoleSignerApplicationStartupError("fixed_signer_admission_runtime_required")
    if admission.context.signer_role != fixed_role or admission.context.signer_service_id != config.signer_id:
        raise FixedRoleSignerApplicationStartupError("fixed_signer_admission_binding_mismatch")
    try:
        engine = engine_factory(config)
    except Exception as exc:
        raise FixedRoleSignerApplicationStartupError("fixed_signer_engine_startup_failed") from exc
    if not isinstance(engine, IndependentSignerEngine):
        raise FixedRoleSignerApplicationStartupError("fixed_signer_engine_required")
    try:
        return create_independent_signer_service(
            engine=engine, service_config=config, admission=admission, clock=clock,
        )
    except Exception as exc:
        raise FixedRoleSignerApplicationStartupError("fixed_signer_service_startup_failed") from exc
