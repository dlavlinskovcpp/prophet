"""Trusted startup construction for the two standalone verifier services."""
from __future__ import annotations

import os
from pathlib import Path

from .independent_zktls_runtime_factory import DeterministicTestIndependentProofChecker, IndependentZkTlsRuntimeFactory
from .resolver_verifier_runtime import ResolverVerifierRuntime
from .runtime_adapter_factory import RuntimeAdapterFactory
from .runtime_config import load_runtime_config
from .signed_oracle_runtime_keys import load_trusted_oracle_key_registry
from .verifier_service import create_verifier_service


VERIFIER_A_ID, VERIFIER_B_ID, VERIFIER_VERSION = "prophet.verifier.runtime.a", "prophet.verifier.runtime.b", "2.0.0"


def _descriptor(identity: str, byte: int):
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": identity, "adapter_version": VERIFIER_VERSION, "implementation_digest": f"{byte:02x}" * 32}


def _runtime_path() -> Path:
    path = os.getenv("PROPHET_VERIFIER_RUNTIME_CONFIG", "")
    if not path: raise ValueError("runtime configuration path is required")
    return Path(path)


def _token(config) -> str:
    token = os.getenv(config.internal_auth.token_env, "")
    if not token: raise ValueError("internal verifier token is required")
    return token


def _build_a(config):
    descriptor = _descriptor(VERIFIER_A_ID, 70)
    signed_registry = None if config.signed_oracle is None else load_trusted_oracle_key_registry(config.signed_oracle.registry_path)
    factory = RuntimeAdapterFactory(runtime_config=config, verifier_descriptors={kind: descriptor for kind in ("zktls", "signed_oracle", "pyth", "chainlink")}, signed_oracle_registry=signed_registry)
    return ResolverVerifierRuntime(config, factory, descriptor)


def _build_b(config):
    if set(config.allowed_adapters) != {"zktls"} or config.mode != "test" or config.zktls.verifier_backend != "deterministic-test":
        raise ValueError("independent verifier backend is not configured")
    descriptor = _descriptor(VERIFIER_B_ID, 71)
    factory = IndependentZkTlsRuntimeFactory(runtime_config=config, verifier_descriptor=descriptor, checker=DeterministicTestIndependentProofChecker())
    return ResolverVerifierRuntime(config, factory, descriptor)


def build_service(kind: str):
    expected_id = VERIFIER_A_ID if kind == "a" else VERIFIER_B_ID
    try:
        config = load_runtime_config(_runtime_path())
        if config.verifier.implementation_id != expected_id or config.verifier.version != VERIFIER_VERSION:
            raise ValueError("service verifier identity mismatch")
        runtime = _build_a(config) if kind == "a" else _build_b(config)
        return create_verifier_service(runtime=runtime, auth_token=_token(config), expected_verifier_id=expected_id, expected_verifier_version=VERIFIER_VERSION, request_max_bytes=config.limits.request_max_bytes, request_timeout_seconds=config.limits.request_timeout_seconds)
    except Exception:
        return create_verifier_service(runtime=None, auth_token="", expected_verifier_id=expected_id, expected_verifier_version=VERIFIER_VERSION, request_max_bytes=1, request_timeout_seconds=1, startup_error="startup_invalid")
