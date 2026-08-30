"""One-shot, role-fixed issuers for existing G1 admission-grant artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

import rfc8785
from solders.keypair import Keypair

from .signer_admission_grant import (
    GRANT_DOMAIN, GRANT_SCHEMA, GRANT_SIGNATURE_SCHEMA, AdmissionGrantError,
    StrictSignerAuthorizationRequestV1, admission_request_binding, decode_strict_json,
)


class FixedRoleAdmissionIssuerError(ValueError):
    """Issuer configuration, input, or key material is unsafe."""


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SECRET_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise FixedRoleAdmissionIssuerError(f"{name}_invalid")
    return value


def _hex(value: Any, length: int, name: str) -> str:
    value = _text(value, name)
    if len(value) != length or any(char not in "0123456789abcdef" for char in value):
        raise FixedRoleAdmissionIssuerError(f"{name}_invalid")
    return value


def _identifier(value: Any, name: str) -> str:
    value = _text(value, name)
    if _IDENTIFIER.fullmatch(value) is None:
        raise FixedRoleAdmissionIssuerError(f"{name}_invalid")
    return value


@dataclass(frozen=True)
class FixedRoleAdmissionIssuerConfig:
    signer_role: str
    signer_service_id: str
    environment: str
    git_sha: str
    evidence_set_id: str
    issuer_id: str
    key_id: str
    issuer_public_key: str
    issuer_private_key_env: str
    ttl_seconds: int
    excluded_public_keys: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Any) -> "FixedRoleAdmissionIssuerConfig":
        fields = {"signer_role", "signer_service_id", "environment", "git_sha", "evidence_set_id", "issuer_id", "key_id", "issuer_public_key", "issuer_private_key_env", "ttl_seconds", "excluded_public_keys"}
        if not isinstance(value, dict) or set(value) != fields:
            raise FixedRoleAdmissionIssuerError("issuer_config_unknown_or_missing_fields")
        excluded = value["excluded_public_keys"]
        if not isinstance(excluded, list) or any(not isinstance(item, str) for item in excluded):
            raise FixedRoleAdmissionIssuerError("excluded_public_keys_invalid")
        return cls(
            value["signer_role"], _identifier(value["signer_service_id"], "signer_service_id"),
            _identifier(value["environment"], "environment"), _hex(value["git_sha"], 40, "git_sha"),
            _identifier(value["evidence_set_id"], "evidence_set_id"), _identifier(value["issuer_id"], "issuer_id"),
            _identifier(value["key_id"], "key_id"), _text(value["issuer_public_key"], "issuer_public_key"),
            _text(value["issuer_private_key_env"], "issuer_private_key_env"), value["ttl_seconds"], tuple(excluded),
        )

    def __post_init__(self) -> None:
        if self.signer_role not in {"A", "B"}:
            raise FixedRoleAdmissionIssuerError("issuer_role_invalid")
        if self.environment not in {"localtest", "public-devnet", "mainnet"}:
            raise FixedRoleAdmissionIssuerError("issuer_environment_invalid")
        if isinstance(self.ttl_seconds, bool) or not isinstance(self.ttl_seconds, int) or not 0 < self.ttl_seconds <= 3600:
            raise FixedRoleAdmissionIssuerError("issuer_ttl_invalid")
        try:
            # Public-key parsing is deliberately performed without reading the private env.
            from solders.pubkey import Pubkey
            public = str(Pubkey.from_string(self.issuer_public_key))
        except Exception as exc:
            raise FixedRoleAdmissionIssuerError("issuer_public_key_invalid") from exc
        if public != self.issuer_public_key:
            raise FixedRoleAdmissionIssuerError("issuer_public_key_invalid")
        if _SECRET_ENV.fullmatch(self.issuer_private_key_env) is None:
            raise FixedRoleAdmissionIssuerError("issuer_private_key_env_invalid")
        peer = "B" if self.signer_role == "A" else "A"
        if f"_{self.signer_role}_" not in f"_{self.issuer_private_key_env}_" or f"_{peer}_" in f"_{self.issuer_private_key_env}_":
            raise FixedRoleAdmissionIssuerError("issuer_private_key_env_role_invalid")
        try:
            excluded = tuple(str(Pubkey.from_string(item)) for item in self.excluded_public_keys)
        except Exception as exc:
            raise FixedRoleAdmissionIssuerError("excluded_public_keys_invalid") from exc
        if excluded != self.excluded_public_keys or public in excluded or len(set(excluded)) != len(excluded):
            raise FixedRoleAdmissionIssuerError("issuer_key_purpose_alias")


def _default_key_loader(config: FixedRoleAdmissionIssuerConfig) -> Keypair:
    raw = os.getenv(config.issuer_private_key_env, "")
    if not raw:
        raise FixedRoleAdmissionIssuerError("issuer_private_key_missing")
    try:
        return Keypair.from_base58_string(raw)
    except Exception as exc:
        raise FixedRoleAdmissionIssuerError("issuer_private_key_invalid") from exc


def _issue_fixed_role_admission_grant(
    *, fixed_role: str, config_value: Mapping[str, Any], raw_request: bytes,
    acceptance_run_id: str, key_loader: Callable[[FixedRoleAdmissionIssuerConfig], Keypair] | None = None,
    clock: Callable[[], datetime] | None = None, token_hex: Callable[[int], str] | None = None,
) -> bytes:
    """Issue one existing G1 artifact; all security fields are issuer-owned."""
    config = FixedRoleAdmissionIssuerConfig.from_mapping(config_value)
    if fixed_role not in {"A", "B"} or config.signer_role != fixed_role:
        raise FixedRoleAdmissionIssuerError("fixed_issuer_role_mismatch")
    try:
        request = StrictSignerAuthorizationRequestV1.from_mapping(decode_strict_json(raw_request))
    except AdmissionGrantError as exc:
        raise FixedRoleAdmissionIssuerError("issuer_request_invalid") from exc
    acceptance_run_id = _hex(acceptance_run_id, 32, "acceptance_run_id")
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise FixedRoleAdmissionIssuerError("issuer_clock_invalid")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    key = (key_loader or _default_key_loader)(config)
    if not isinstance(key, Keypair) or str(key.pubkey()) != config.issuer_public_key:
        raise FixedRoleAdmissionIssuerError("issuer_key_binding_invalid")
    _, _, request_digest = admission_request_binding(request)
    grant = {
        "schema": GRANT_SCHEMA, "version": 1,
        "grant_id": (token_hex or secrets.token_hex)(16), "environment": config.environment,
        "git_sha": config.git_sha, "evidence_set_id": config.evidence_set_id,
        "acceptance_run_id": acceptance_run_id, "signer_role": fixed_role,
        "signer_service_id": config.signer_service_id, "admission_request_sha256": request_digest,
        "issuer_id": config.issuer_id, "key_id": config.key_id,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valid_until": (now + timedelta(seconds=config.ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if not isinstance(grant["grant_id"], str) or len(grant["grant_id"]) != 32 or any(c not in "0123456789abcdef" for c in grant["grant_id"]):
        raise FixedRoleAdmissionIssuerError("issuer_randomness_invalid")
    jcs = rfc8785.dumps(grant)
    preimage = GRANT_DOMAIN + len(jcs).to_bytes(4, "little") + jcs
    envelope = {
        "schema": GRANT_SIGNATURE_SCHEMA, "version": 1, "algorithm": "ed25519",
        "issuer_id": config.issuer_id, "key_id": config.key_id,
        "signed_payload_sha256": hashlib.sha256(preimage).hexdigest(),
        "signature": bytes(key.sign_message(preimage)).hex(),
    }
    return json.dumps({"unsigned_grant": grant, "signature_envelope": envelope}, separators=(",", ":")).encode("utf-8")


def validate_role_local_issuer_isolation(
    issuer_a: FixedRoleAdmissionIssuerConfig,
    issuer_b: FixedRoleAdmissionIssuerConfig,
) -> None:
    """Reject any A/B issuer identity or key-source overlap before operation."""
    if issuer_a.signer_role != "A" or issuer_b.signer_role != "B":
        raise FixedRoleAdmissionIssuerError("issuer_role_pair_invalid")
    if issuer_a.issuer_public_key == issuer_b.issuer_public_key:
        raise FixedRoleAdmissionIssuerError("issuer_key_pair_alias")
    if issuer_a.issuer_private_key_env == issuer_b.issuer_private_key_env:
        raise FixedRoleAdmissionIssuerError("issuer_key_source_pair_alias")
