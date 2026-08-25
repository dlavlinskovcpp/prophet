"""Pure operated-deployment acceptance for two independent signer services.

This module validates supplied, public deployment declarations.  It does not
prove that declarations match physical infrastructure and intentionally never
constructs a signer engine, HTTP service, journal, Vault client, or RPC client.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Any, Mapping

from solders.pubkey import Pubkey

from .independent_signer_runtime import (
    IndependentSignerServiceConfig,
    IndependentSignerTopologyError,
    validate_independent_signer_topology,
)


_DOMAIN = b"PROPHET_INDEPENDENT_SIGNER_DEPLOYMENT_V1\0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_ENVIRONMENTS = frozenset(("localtest", "public-devnet", "mainnet"))
_FIELDS = frozenset((
    "service_config_fingerprint", "signer_role", "signer_id", "signer_public_key",
    "deployment_environment", "deployment_host_id", "runtime_principal_id",
    "runtime_admin_domain_id", "service_instance_id", "listen_scheme",
    "externally_exposed_scheme", "tls_termination_domain_id", "server_worker_count",
    "execution_concurrency_limit", "reload_enabled", "journal_storage_domain_id",
    "audit_domain_id",
))


class IndependentSignerDeploymentManifestError(ValueError):
    """Raised for a malformed deployment declaration."""


class IndependentSignerDeploymentAcceptanceError(ValueError):
    """Raised when declarations cannot support operated 2-of-2 signing."""


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise IndependentSignerDeploymentManifestError(f"{name}_invalid")
    return value


def _fingerprint(value: Any, name: str) -> str:
    value = _text(value, name)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise IndependentSignerDeploymentManifestError(f"{name}_invalid")
    return value


def _pubkey(value: Any, name: str) -> str:
    value = _text(value, name)
    try:
        if str(Pubkey.from_string(value)) != value:
            raise ValueError
    except Exception as exc:
        raise IndependentSignerDeploymentManifestError(f"{name}_invalid") from exc
    return value


def _positive(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise IndependentSignerDeploymentManifestError(f"{name}_invalid")
    return value


def _encoded(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<H", len(raw)) + raw


@dataclass(frozen=True)
class IndependentSignerDeploymentManifest:
    """Immutable, public declaration for exactly one signer-service process."""

    service_config_fingerprint: str
    signer_role: str
    signer_id: str
    signer_public_key: str
    deployment_environment: str
    deployment_host_id: str
    runtime_principal_id: str
    runtime_admin_domain_id: str
    service_instance_id: str
    listen_scheme: str
    externally_exposed_scheme: str
    tls_termination_domain_id: str
    server_worker_count: int
    execution_concurrency_limit: int
    reload_enabled: bool
    journal_storage_domain_id: str
    audit_domain_id: str

    def __post_init__(self) -> None:
        _fingerprint(self.service_config_fingerprint, "service_config_fingerprint")
        if self.signer_role not in ("A", "B"):
            raise IndependentSignerDeploymentManifestError("signer_role_invalid")
        _text(self.signer_id, "signer_id")
        _pubkey(self.signer_public_key, "signer_public_key")
        if self.deployment_environment not in _ENVIRONMENTS:
            raise IndependentSignerDeploymentManifestError("deployment_environment_invalid")
        for name in (
            "deployment_host_id", "runtime_principal_id", "runtime_admin_domain_id",
            "service_instance_id", "tls_termination_domain_id", "journal_storage_domain_id",
            "audit_domain_id",
        ):
            _text(getattr(self, name), name)
        if self.listen_scheme not in ("http", "https"):
            raise IndependentSignerDeploymentManifestError("listen_scheme_invalid")
        if self.externally_exposed_scheme not in ("http", "https"):
            raise IndependentSignerDeploymentManifestError("externally_exposed_scheme_invalid")
        _positive(self.server_worker_count, "server_worker_count")
        _positive(self.execution_concurrency_limit, "execution_concurrency_limit")
        if self.reload_enabled is not False:
            raise IndependentSignerDeploymentManifestError("reload_enabled_must_be_false")

    @classmethod
    def from_mapping(cls, value: Any) -> "IndependentSignerDeploymentManifest":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise IndependentSignerDeploymentManifestError("deployment_manifest_unknown_or_missing_fields")
        return cls(**value)

    def fingerprint(self) -> str:
        parts = (
            self.service_config_fingerprint, self.signer_role, self.signer_id,
            self.signer_public_key, self.deployment_environment, self.deployment_host_id,
            self.runtime_principal_id, self.runtime_admin_domain_id, self.service_instance_id,
            self.listen_scheme, self.externally_exposed_scheme, self.tls_termination_domain_id,
            str(self.server_worker_count), str(self.execution_concurrency_limit),
            "false", self.journal_storage_domain_id, self.audit_domain_id,
        )
        return hashlib.sha256(_DOMAIN + b"".join(_encoded(part) for part in parts)).hexdigest()

    def validate_config_binding(self, config: IndependentSignerServiceConfig) -> None:
        if not isinstance(config, IndependentSignerServiceConfig):
            raise IndependentSignerDeploymentAcceptanceError("independent_signer_config_required")
        if (
            self.service_config_fingerprint != config.fingerprint()
            or self.signer_role != config.signer_role
            or self.signer_id != config.signer_id
            or self.signer_public_key != config.signer_public_key
            or self.deployment_environment != config.environment
        ):
            raise IndependentSignerDeploymentAcceptanceError("deployment_manifest_config_binding_mismatch")
        if config.environment in ("public-devnet", "mainnet") and (
            self.externally_exposed_scheme != "https" or not self.tls_termination_domain_id
        ):
            raise IndependentSignerDeploymentAcceptanceError("production_tls_ingress_required")


@dataclass(frozen=True)
class OperatedDeploymentAcceptance:
    """Capability-free evidence that declarations satisfy the operated policy.

    This result is not evidence that hosts, cloud accounts, or providers are
    physically independent; that needs separately collected operational proof.
    """

    schema: str
    version: int
    environment: str
    signer_a_service_config_fingerprint: str
    signer_b_service_config_fingerprint: str
    signer_a_deployment_fingerprint: str
    signer_b_deployment_fingerprint: str
    classification: str


def _distinct(left: Any, right: Any, attribute: str) -> None:
    if getattr(left, attribute) == getattr(right, attribute):
        raise IndependentSignerDeploymentAcceptanceError(f"{attribute}_collision")


def _require_operated_process_model(manifest: IndependentSignerDeploymentManifest) -> None:
    if manifest.server_worker_count != 1:
        raise IndependentSignerDeploymentAcceptanceError("operated_server_worker_count_must_be_one")
    if manifest.execution_concurrency_limit != 1:
        raise IndependentSignerDeploymentAcceptanceError("operated_execution_concurrency_limit_must_be_one")


def validate_operated_signer_deployment(
    config_a: IndependentSignerServiceConfig,
    config_b: IndependentSignerServiceConfig,
    manifest_a: IndependentSignerDeploymentManifest,
    manifest_b: IndependentSignerDeploymentManifest,
) -> OperatedDeploymentAcceptance:
    """Accept two declared services only when they satisfy operated 2-of-2 policy.

    This is pure configuration validation.  It reuses P0C3A for all signer,
    Vault, RPC, and base journal topology decisions rather than reimplementing
    that trust logic.
    """
    if not isinstance(manifest_a, IndependentSignerDeploymentManifest) or not isinstance(manifest_b, IndependentSignerDeploymentManifest):
        raise IndependentSignerDeploymentAcceptanceError("deployment_manifests_required")
    try:
        topology = validate_independent_signer_topology(config_a, config_b)
    except IndependentSignerTopologyError as exc:
        raise IndependentSignerDeploymentAcceptanceError("p0c3a_topology_rejected") from exc
    if topology != "OPERATED_2OF2_ACCEPTABLE":
        raise IndependentSignerDeploymentAcceptanceError("operated_topology_required")
    manifest_a.validate_config_binding(config_a)
    manifest_b.validate_config_binding(config_b)
    _require_operated_process_model(manifest_a)
    _require_operated_process_model(manifest_b)
    if config_a.mode != "production" or config_b.mode != "production" or config_a.environment not in ("public-devnet", "mainnet"):
        raise IndependentSignerDeploymentAcceptanceError("operated_production_environment_required")
    pairs = ((config_a, manifest_a), (config_b, manifest_b))
    by_role = {config.signer_role: (config, manifest) for config, manifest in pairs}
    if set(by_role) != {"A", "B"}:
        raise IndependentSignerDeploymentAcceptanceError("manifest_roles_must_be_a_and_b")
    signer_a_config, signer_a_manifest = by_role["A"]
    signer_b_config, signer_b_manifest = by_role["B"]
    for attribute in (
        "deployment_host_id", "runtime_principal_id", "runtime_admin_domain_id",
        "service_instance_id", "journal_storage_domain_id", "audit_domain_id",
        "tls_termination_domain_id",
    ):
        _distinct(signer_a_manifest, signer_b_manifest, attribute)
    for attribute in ("vault_token_env", "admission_token_env", "rpc_url_env"):
        _distinct(signer_a_config, signer_b_config, attribute)
    return OperatedDeploymentAcceptance(
        schema="PROPHET_OPERATED_SIGNER_DEPLOYMENT_ACCEPTANCE_V1",
        version=1,
        environment=signer_a_config.environment,
        signer_a_service_config_fingerprint=signer_a_config.fingerprint(),
        signer_b_service_config_fingerprint=signer_b_config.fingerprint(),
        signer_a_deployment_fingerprint=signer_a_manifest.fingerprint(),
        signer_b_deployment_fingerprint=signer_b_manifest.fingerprint(),
        classification="OPERATED_2OF2_ACCEPTABLE",
    )
