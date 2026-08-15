"""Trusted startup construction for the standalone coordinator HTTP service."""
from __future__ import annotations

import os
from pathlib import Path

from .coordinator_service import create_coordinator_service
from .resolution_coordinator import ResolutionCoordinator
from .resolution_coordinator_store import ResolutionCoordinatorStore, VerifierBinding
from .runtime_config import load_runtime_config
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
        config = load_runtime_config(_runtime_path())
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
