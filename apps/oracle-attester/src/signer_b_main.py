"""Signer-B production entry identity; no caller-selected role exists here."""
from collections.abc import Callable, Mapping
from typing import Any

from .fixed_role_signer import load_fixed_role_config
from .fixed_role_signer_application import create_fixed_role_signer_application
from .independent_signer_execution import IndependentSignerEngine
from .independent_signer_runtime import IndependentSignerServiceConfig
from .signer_admission_runtime import SignerAdmissionRuntime

FIXED_SIGNER_ROLE = "B"


def load_signer_b_config(value):
    return load_fixed_role_config(FIXED_SIGNER_ROLE, value)


def create_signer_b_application(
    config_value: Mapping[str, Any], *,
    admission_factory: Callable[[IndependentSignerServiceConfig], SignerAdmissionRuntime],
    engine_factory: Callable[[IndependentSignerServiceConfig], IndependentSignerEngine],
    clock: Callable[[], Any] | None = None,
):
    return create_fixed_role_signer_application(
        fixed_role=FIXED_SIGNER_ROLE, config_value=config_value,
        admission_factory=admission_factory, engine_factory=engine_factory, clock=clock,
    )
