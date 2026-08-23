"""Pure configuration and topology validation for one independent signer.

This P0C3A boundary deliberately does not construct Vault, RPC, journal, or
HTTP clients.  A process receives one ``IndependentSignerServiceConfig`` only;
the A/B comparison is an explicit deployment-time operation over two separate
service configurations.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from solders.pubkey import Pubkey


_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_FINGERPRINT_DOMAIN = b"PROPHET_INDEPENDENT_SIGNER_SERVICE_CONFIG_V1\0"
_ENVIRONMENTS = frozenset(("localtest", "public-devnet", "mainnet"))
_MODES = frozenset(("test", "production"))
_TOPOLOGIES = frozenset(("OPERATED_2OF2", "FUNCTIONAL_TEST_ONLY"))


class IndependentSignerRuntimeConfigError(ValueError):
    """Raised for malformed or unsafe one-signer configuration."""


class IndependentSignerTopologyError(IndependentSignerRuntimeConfigError):
    """Raised when A/B service topology is not independently operated."""


def _object(value: Any, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise IndependentSignerRuntimeConfigError(f"{name}_unknown_or_missing_fields")
    return value


def _text(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise IndependentSignerRuntimeConfigError(f"{name}_invalid")
    return value


def _env(value: Any, name: str) -> str:
    value = _text(value, name)
    if not _ENV_NAME.fullmatch(value):
        raise IndependentSignerRuntimeConfigError(f"{name}_invalid")
    return value


def _positive(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise IndependentSignerRuntimeConfigError(f"{name}_invalid")
    return value


def _hash(value: Any, name: str) -> str:
    value = _text(value, name, 64)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise IndependentSignerRuntimeConfigError(f"{name}_invalid")
    return value


def _pubkey(value: Any, name: str) -> str:
    value = _text(value, name)
    try:
        if str(Pubkey.from_string(value)) != value:
            raise ValueError
    except Exception as exc:
        raise IndependentSignerRuntimeConfigError(f"{name}_invalid") from exc
    return value


def _url(value: Any, name: str, *, require_https: bool) -> str:
    value = _text(value, name)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise IndependentSignerRuntimeConfigError(f"{name}_invalid") from exc
    schemes = {"https"} if require_https else {"http", "https"}
    if (parsed.scheme not in schemes or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or port == 0):
        raise IndependentSignerRuntimeConfigError(f"{name}_invalid")
    return value.rstrip("/")


def canonicalize_journal_path(path: Any, *, require_absolute: bool = False) -> str:
    """Return a non-creating canonical journal identity for topology checks."""
    path = _text(path, "journal_path", 4096)
    if "\x00" in path or path == ":memory:" or path.lower().startswith(("http:", "https:")):
        raise IndependentSignerRuntimeConfigError("journal_path_invalid")
    candidate = Path(path)
    if require_absolute and not candidate.is_absolute():
        raise IndependentSignerRuntimeConfigError("production_journal_path_not_absolute")
    try:
        # strict=False resolves all observable components but never creates the
        # journal file or its parent directories.
        return str(candidate.resolve(strict=False))
    except (OSError, RuntimeError, ValueError) as exc:
        raise IndependentSignerRuntimeConfigError("journal_path_invalid") from exc


def _encoded(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 0xFFFF:
        raise IndependentSignerRuntimeConfigError("fingerprint_text_too_long")
    return struct.pack("<H", len(raw)) + raw


@dataclass(frozen=True)
class IndependentSignerServiceConfig:
    """Immutable public configuration for exactly one signer process."""

    environment: str
    mode: str
    topology_classification: str
    signer_role: str
    signer_id: str
    signer_public_key: str
    signer_key_version: int
    vault_address: str
    vault_transit_mount: str
    vault_key_name: str
    vault_token_env: str
    vault_admin_domain_id: str
    vault_account_or_tenant_id: str
    vault_auth_principal_id: str
    vault_timeout_seconds: int
    rpc_url_env: str
    rpc_provider_domain_id: str
    rpc_account_or_project_id: str
    rpc_credential_principal_id: str
    expected_genesis_hash: str
    expected_program_id: str
    journal_path: str
    admission_token_env: str
    journal_path_identity: str = field(init=False)

    def __post_init__(self) -> None:
        if self.environment not in _ENVIRONMENTS:
            raise IndependentSignerRuntimeConfigError("environment_invalid")
        if self.mode not in _MODES:
            raise IndependentSignerRuntimeConfigError("mode_invalid")
        if self.topology_classification not in _TOPOLOGIES:
            raise IndependentSignerRuntimeConfigError("topology_classification_invalid")
        if self.topology_classification == "FUNCTIONAL_TEST_ONLY" and (self.environment != "localtest" or self.mode != "test"):
            raise IndependentSignerRuntimeConfigError("functional_test_topology_not_localtest")
        if self.signer_role not in ("A", "B"):
            raise IndependentSignerRuntimeConfigError("signer_role_invalid")
        _text(self.signer_id, "signer_id")
        _pubkey(self.signer_public_key, "signer_public_key")
        _positive(self.signer_key_version, "signer_key_version")
        _url(self.vault_address, "vault_address", require_https=self.environment in ("public-devnet", "mainnet"))
        _text(self.vault_transit_mount, "vault_transit_mount")
        _text(self.vault_key_name, "vault_key_name")
        _env(self.vault_token_env, "vault_token_env")
        _text(self.vault_admin_domain_id, "vault_admin_domain_id")
        _text(self.vault_account_or_tenant_id, "vault_account_or_tenant_id")
        _text(self.vault_auth_principal_id, "vault_auth_principal_id")
        _positive(self.vault_timeout_seconds, "vault_timeout_seconds")
        _env(self.rpc_url_env, "rpc_url_env")
        _text(self.rpc_provider_domain_id, "rpc_provider_domain_id")
        _text(self.rpc_account_or_project_id, "rpc_account_or_project_id")
        _text(self.rpc_credential_principal_id, "rpc_credential_principal_id")
        _hash(self.expected_genesis_hash, "expected_genesis_hash")
        _pubkey(self.expected_program_id, "expected_program_id")
        identity = canonicalize_journal_path(
            self.journal_path,
            require_absolute=self.environment in ("public-devnet", "mainnet"),
        )
        object.__setattr__(self, "journal_path_identity", identity)
        _env(self.admission_token_env, "admission_token_env")

    @classmethod
    def from_mapping(cls, value: Any) -> "IndependentSignerServiceConfig":
        fields = {
            "environment", "mode", "topology_classification", "signer", "vault",
            "rpc", "solana", "journal_path", "admission_token_env",
        }
        row = _object(value, fields, "independent_signer_service")
        signer = _object(row["signer"], {"role", "signer_id", "public_key", "key_version"}, "signer")
        vault = _object(row["vault"], {
            "address", "transit_mount", "key_name", "token_env", "admin_domain_id",
            "account_or_tenant_id", "auth_principal_id", "timeout_seconds",
        }, "vault")
        rpc = _object(row["rpc"], {
            "url_env", "provider_domain_id", "account_or_project_id", "credential_principal_id",
        }, "rpc")
        solana = _object(row["solana"], {"expected_genesis_hash", "expected_program_id"}, "solana")
        return cls(
            _text(row["environment"], "environment"), _text(row["mode"], "mode"),
            _text(row["topology_classification"], "topology_classification"),
            _text(signer["role"], "signer.role"), _text(signer["signer_id"], "signer.signer_id"),
            _pubkey(signer["public_key"], "signer.public_key"), _positive(signer["key_version"], "signer.key_version"),
            _url(vault["address"], "vault.address", require_https=row["environment"] in ("public-devnet", "mainnet")),
            _text(vault["transit_mount"], "vault.transit_mount"), _text(vault["key_name"], "vault.key_name"),
            _env(vault["token_env"], "vault.token_env"), _text(vault["admin_domain_id"], "vault.admin_domain_id"),
            _text(vault["account_or_tenant_id"], "vault.account_or_tenant_id"), _text(vault["auth_principal_id"], "vault.auth_principal_id"),
            _positive(vault["timeout_seconds"], "vault.timeout_seconds"), _env(rpc["url_env"], "rpc.url_env"),
            _text(rpc["provider_domain_id"], "rpc.provider_domain_id"), _text(rpc["account_or_project_id"], "rpc.account_or_project_id"),
            _text(rpc["credential_principal_id"], "rpc.credential_principal_id"),
            _hash(solana["expected_genesis_hash"], "solana.expected_genesis_hash"),
            _pubkey(solana["expected_program_id"], "solana.expected_program_id"),
            _text(row["journal_path"], "journal_path", 4096), _env(row["admission_token_env"], "admission_token_env"),
        )

    def fingerprint(self) -> str:
        parts = (
            self.environment, self.mode, self.topology_classification, self.signer_role,
            self.signer_id, self.signer_public_key, str(self.signer_key_version),
            self.vault_address, self.vault_transit_mount, self.vault_key_name,
            self.vault_token_env, self.vault_admin_domain_id, self.vault_account_or_tenant_id,
            self.vault_auth_principal_id, str(self.vault_timeout_seconds), self.rpc_url_env,
            self.rpc_provider_domain_id, self.rpc_account_or_project_id,
            self.rpc_credential_principal_id, self.expected_genesis_hash,
            self.expected_program_id, self.journal_path, self.journal_path_identity, self.admission_token_env,
        )
        return hashlib.sha256(_FINGERPRINT_DOMAIN + b"".join(_encoded(item) for item in parts)).hexdigest()


def _require_distinct(config_a: IndependentSignerServiceConfig, config_b: IndependentSignerServiceConfig, attribute: str, error: str) -> None:
    if getattr(config_a, attribute) == getattr(config_b, attribute):
        raise IndependentSignerTopologyError(error)


def validate_independent_signer_topology(
    config_a: IndependentSignerServiceConfig,
    config_b: IndependentSignerServiceConfig,
) -> str:
    """Validate two service-local configs without making any external call.

    Returns ``OPERATED_2OF2_ACCEPTABLE`` only for a fully independent topology;
    a deliberately correlated localtest pair is visibly classified as
    ``FUNCTIONAL_TEST_ONLY`` and cannot become deployable production topology.
    """
    if not isinstance(config_a, IndependentSignerServiceConfig) or not isinstance(config_b, IndependentSignerServiceConfig):
        raise IndependentSignerTopologyError("independent_signer_configs_required")
    if {config_a.signer_role, config_b.signer_role} != {"A", "B"}:
        raise IndependentSignerTopologyError("signer_roles_must_be_a_and_b")
    for attribute, error in (
        ("signer_id", "signer_id_collision"),
        ("signer_public_key", "signer_public_key_collision"),
        ("vault_key_name", "vault_key_collision"),
        ("journal_path_identity", "journal_path_collision"),
        ("admission_token_env", "admission_token_env_collision"),
    ):
        _require_distinct(config_a, config_b, attribute, error)
    if config_a.environment != config_b.environment or config_a.mode != config_b.mode:
        raise IndependentSignerTopologyError("environment_or_mode_mismatch")
    if config_a.expected_genesis_hash != config_b.expected_genesis_hash or config_a.expected_program_id != config_b.expected_program_id:
        raise IndependentSignerTopologyError("solana_identity_mismatch")
    functional = config_a.topology_classification == config_b.topology_classification == "FUNCTIONAL_TEST_ONLY"
    if functional:
        if config_a.environment != "localtest" or config_a.mode != "test":
            raise IndependentSignerTopologyError("functional_test_topology_not_localtest")
        return "FUNCTIONAL_TEST_ONLY"
    if config_a.topology_classification != "OPERATED_2OF2" or config_b.topology_classification != "OPERATED_2OF2":
        raise IndependentSignerTopologyError("topology_classification_mismatch")
    for attribute, error in (
        ("vault_auth_principal_id", "vault_auth_principal_collision"),
        ("vault_admin_domain_id", "vault_admin_domain_collision"),
        ("vault_account_or_tenant_id", "vault_account_or_tenant_collision"),
        ("rpc_credential_principal_id", "rpc_credential_principal_collision"),
        ("rpc_provider_domain_id", "rpc_provider_domain_collision"),
        ("rpc_account_or_project_id", "rpc_account_or_project_collision"),
    ):
        _require_distinct(config_a, config_b, attribute, error)
    return "OPERATED_2OF2_ACCEPTABLE"
