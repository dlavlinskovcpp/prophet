"""Trusted startup construction for the standalone coordinator HTTP service."""
from __future__ import annotations

import os
from pathlib import Path

from .coordinator_service import create_coordinator_service
from .resolution_coordinator import ResolutionCoordinator
from .resolution_coordinator_store import ResolutionCoordinatorStore, VerifierBinding
from .runtime_config import load_runtime_config
from .secure_settlement_runtime import (
    SecureSettlementRuntimeError,
    load_secure_settlement_runtime,
)
from .verifier_service_client import VerifierServiceClient


def _runtime_path() -> Path:
    path = os.getenv("PROPHET_COORDINATOR_RUNTIME_CONFIG", "")
    if not path:
        raise ValueError("coordinator runtime configuration path is required")
    return Path(path)


def _descriptor(config):
    return {
        "schema": "prophet.adapter-descriptor.v2",
        "schema_version": "2.0.0",
        "adapter_id": config.expected_verifier_id,
        "adapter_version": config.expected_verifier_version,
        "implementation_digest": config.expected_verifier_implementation_digest,
    }


def build_coordinator_service():
    resources = []
    try:
        runtime_path = _runtime_path()
        require_settlement_context = False
        try:
            secure = load_secure_settlement_runtime(
                runtime_path,
                enable_mainnet=os.getenv("PROPHET_ENABLE_MAINNET_SETTLEMENT", "") == "1",
            )
        except SecureSettlementRuntimeError:
            # Preserve the existing local/test coordinator contract. Production
            # must never fall back to the legacy runtime-only topology.
            config = load_runtime_config(runtime_path)
            if config.mode == "production":
                raise ValueError("production coordinator requires secure settlement runtime")
        else:
            config = secure.runtime
            require_settlement_context = True
        if config.coordinator is None:
            raise ValueError("coordinator configuration is required")
        token = os.getenv(config.coordinator.internal_auth.token_env, "")
        if not token:
            raise ValueError("coordinator internal token is required")
        state = ResolutionCoordinatorStore(
            config.coordinator.sqlite_path,
            verifier_a=VerifierBinding("A", _descriptor(config.coordinator.verifier_a)),
            verifier_b=VerifierBinding("B", _descriptor(config.coordinator.verifier_b)),
        )
        resources.append(state)
        client_a = VerifierServiceClient.from_runtime(config, slot="A")
        client_b = VerifierServiceClient.from_runtime(config, slot="B")
        resources.extend((client_a, client_b))
        coordinator = ResolutionCoordinator(state=state, verifier_client_a=client_a, verifier_client_b=client_b)
        return create_coordinator_service(
            coordinator=coordinator,
            state=state,
            auth_token=token,
            request_max_bytes=config.limits.request_max_bytes,
            request_timeout_seconds=config.coordinator.request_timeout_seconds,
            close_resources=True,
            solana_runtime=config.solana if require_settlement_context else None,
            require_settlement_context=require_settlement_context,
        )
    except Exception:
        for resource in reversed(resources):
            close = getattr(resource, "close", None)
            if close is not None:
                close()
        return create_coordinator_service(
            request_max_bytes=1,
            request_timeout_seconds=1,
            startup_error="startup_invalid",
        )
