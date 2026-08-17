"""Mandatory production settlement topology validation.

This layer is additive to ResolverRuntimeConfig. It consumes one extra
`secure_settlement` object from the same YAML file, then delegates all existing
Resolver/settlement parsing to runtime_config without changing canonical bytes.
"""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from .runtime_config import ResolverRuntimeConfig, RuntimeConfigError, parse_runtime_config


class SecureSettlementRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class SecureSettlementPolicy:
    resolution_mode: str
    direct_attester_settlement_enabled: bool
    generic_remote_signer_settlement_enabled: bool
    required_signer_count: int
    api_auth_token_env: str
    signer_a_vault_token_env: str
    signer_b_vault_token_env: str


@dataclass(frozen=True)
class SecureSettlementRuntime:
    runtime: ResolverRuntimeConfig
    policy: SecureSettlementPolicy


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SecureSettlementRuntimeError(f"{name}_required")
    return value.strip()


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise SecureSettlementRuntimeError(f"{name}_must_be_boolean")
    return value


def _persistent(path: str | None, name: str) -> None:
    if not path or path == ":memory:" or not Path(path).is_absolute():
        raise SecureSettlementRuntimeError(f"{name}_must_be_persistent_absolute_path")


def _policy(value: Any) -> SecureSettlementPolicy:
    keys = {
        "resolution_mode",
        "direct_attester_settlement_enabled",
        "generic_remote_signer_settlement_enabled",
        "required_signer_count",
        "api_auth_token_env",
        "signer_a_vault_token_env",
        "signer_b_vault_token_env",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise SecureSettlementRuntimeError("secure_settlement_policy_shape_invalid")
    count = value["required_signer_count"]
    if isinstance(count, bool) or not isinstance(count, int):
        raise SecureSettlementRuntimeError("required_signer_count_invalid")
    return SecureSettlementPolicy(
        resolution_mode=_text(value["resolution_mode"], "resolution_mode"),
        direct_attester_settlement_enabled=_bool(
            value["direct_attester_settlement_enabled"],
            "direct_attester_settlement_enabled",
        ),
        generic_remote_signer_settlement_enabled=_bool(
            value["generic_remote_signer_settlement_enabled"],
            "generic_remote_signer_settlement_enabled",
        ),
        required_signer_count=count,
        api_auth_token_env=_text(value["api_auth_token_env"], "api_auth_token_env"),
        signer_a_vault_token_env=_text(
            value["signer_a_vault_token_env"], "signer_a_vault_token_env"
        ),
        signer_b_vault_token_env=_text(
            value["signer_b_vault_token_env"], "signer_b_vault_token_env"
        ),
    )


def validate_secure_settlement_topology(
    runtime: ResolverRuntimeConfig, policy: SecureSettlementPolicy
) -> None:
    if policy.resolution_mode != "secure-coordinator":
        raise SecureSettlementRuntimeError("secure_coordinator_mode_required")
    if policy.direct_attester_settlement_enabled:
        raise SecureSettlementRuntimeError("direct_attester_settlement_forbidden")
    if policy.generic_remote_signer_settlement_enabled:
        raise SecureSettlementRuntimeError("generic_remote_signer_settlement_forbidden")
    if policy.required_signer_count != 2:
        raise SecureSettlementRuntimeError("strict_2of2_required")
    if runtime.coordinator is None:
        raise SecureSettlementRuntimeError("coordinator_configuration_required")
    if runtime.signing is None:
        raise SecureSettlementRuntimeError("signing_configuration_required")
    if runtime.settlement_execution is None:
        raise SecureSettlementRuntimeError("settlement_execution_configuration_required")

    coordinator = runtime.coordinator
    if coordinator.verifier_a.base_url.rstrip("/") == coordinator.verifier_b.base_url.rstrip("/"):
        raise SecureSettlementRuntimeError("verifier_service_urls_must_be_distinct")
    if coordinator.verifier_a.auth_token_env == coordinator.verifier_b.auth_token_env:
        raise SecureSettlementRuntimeError("verifier_auth_refs_must_be_distinct")
    _persistent(coordinator.sqlite_path, "coordinator_sqlite_path")

    signing = runtime.signing
    _persistent(signing.journal_path, "signing_journal_path")
    _persistent(runtime.settlement_execution.journal_path, "submission_journal_path")
    if signing.backend != "vault-transit":
        raise SecureSettlementRuntimeError("production_vault_transit_required")
    if (
        signing.signer_a.signer_id == signing.signer_b.signer_id
        or signing.signer_a.key_name == signing.signer_b.key_name
        or signing.signer_a.expected_public_key == signing.signer_b.expected_public_key
    ):
        raise SecureSettlementRuntimeError("signer_domains_must_be_distinct")
    if policy.signer_a_vault_token_env == policy.signer_b_vault_token_env:
        raise SecureSettlementRuntimeError("signer_vault_auth_refs_must_be_distinct")
    if signing.token_env in {
        policy.signer_a_vault_token_env,
        policy.signer_b_vault_token_env,
    }:
        raise SecureSettlementRuntimeError("legacy_shared_vault_auth_must_be_separate")
    if policy.api_auth_token_env in {
        policy.signer_a_vault_token_env,
        policy.signer_b_vault_token_env,
        coordinator.internal_auth.token_env,
    }:
        raise SecureSettlementRuntimeError("settlement_api_auth_must_not_be_signer_auth")
    if runtime.mode != "production":
        raise SecureSettlementRuntimeError("secure_settlement_runtime_must_be_production")
    if runtime.environment not in {"public-devnet", "mainnet"}:
        raise SecureSettlementRuntimeError("secure_settlement_environment_invalid")


def load_secure_settlement_runtime(
    path: str | Path, *, enable_mainnet: bool = False
) -> SecureSettlementRuntime:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SecureSettlementRuntimeError("secure_runtime_load_failed") from exc
    if not isinstance(raw, dict) or "secure_settlement" not in raw:
        raise SecureSettlementRuntimeError("secure_settlement_policy_required")
    core = dict(raw)
    policy = _policy(core.pop("secure_settlement"))
    try:
        runtime = parse_runtime_config(core, enable_mainnet=enable_mainnet)
    except RuntimeConfigError as exc:
        raise SecureSettlementRuntimeError("resolver_runtime_invalid") from exc
    validate_secure_settlement_topology(runtime, policy)
    return SecureSettlementRuntime(runtime=runtime, policy=policy)


def load_secure_auth_tokens(
    config: SecureSettlementRuntime, environ: Mapping[str, str] | None = None
) -> tuple[str, str, str]:
    source = os.environ if environ is None else environ
    policy, signing = config.policy, config.runtime.signing
    assert signing is not None
    if source.get(signing.token_env, ""):
        raise SecureSettlementRuntimeError("legacy_shared_vault_token_must_be_unset")
    api = source.get(policy.api_auth_token_env, "")
    token_a = source.get(policy.signer_a_vault_token_env, "")
    token_b = source.get(policy.signer_b_vault_token_env, "")
    if not api:
        raise SecureSettlementRuntimeError("secure_settlement_api_token_missing")
    if not token_a or not token_b:
        raise SecureSettlementRuntimeError("signer_vault_tokens_missing")
    if hmac.compare_digest(token_a, token_b):
        raise SecureSettlementRuntimeError("signer_vault_tokens_must_be_distinct")
    if hmac.compare_digest(api, token_a) or hmac.compare_digest(api, token_b):
        raise SecureSettlementRuntimeError("api_token_must_not_equal_vault_token")
    return api, token_a, token_b
