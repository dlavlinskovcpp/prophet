"""One-signer execution core for the P0C1 -> P0C2 signing boundary.

This module intentionally has no HTTP server, coordinator, transaction, fee
payer, or second-signer dependency.  Its only public operation accepts an
untrusted P0C1 authorization request; arbitrary bytes never reach Vault.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from solders.pubkey import Pubkey
from solders.signature import Signature

from .independent_signer_journal import (
    CONFLICT, PREPARED, SIGNED, SIGNING, UNCERTAIN,
    IndependentJournalRecord, IndependentSignerJournal, IndependentSignerJournalStateError,
)
from .independent_signer_runtime import IndependentSignerServiceConfig
from .signer_authorization import FinalizedRpc, SignerAuthorizationConfig, authorize_for_journal
from .vault_transit import VaultTransitClient, VaultTransitConfig, VaultTransitError, parse_vault_public_key


class IndependentSignerExecutionError(RuntimeError):
    """Safe failure at the one-signer execution boundary."""


class IndependentSignerStartupError(IndependentSignerExecutionError):
    """Raised before the engine is usable when local bindings disagree."""


class IndependentSignerVaultError(IndependentSignerExecutionError):
    """Raised for a pinned single-Vault metadata or signing failure."""


class _VaultTransport(Protocol):
    def read_key_metadata(self, key_name: str) -> Mapping[str, Any]: ...
    def sign_versioned(self, key_name: str, message: bytes, *, key_version: int) -> tuple[int, bytes]: ...


@dataclass(frozen=True)
class IndependentSignerVaultIdentity:
    signer_id: str
    public_key: str
    key_version: int
    vault_key_name: str


@dataclass(frozen=True)
class _VaultSignature:
    signer_id: str
    public_key: str
    key_version: int
    canonical_message_digest: str
    signature: bytes


class IndependentSignerVaultAdapter:
    """Pinned one-key Vault Transit boundary; it has no public byte-sign API."""

    def __init__(self, config: IndependentSignerServiceConfig, *, transport: _VaultTransport | None = None) -> None:
        if not isinstance(config, IndependentSignerServiceConfig):
            raise IndependentSignerStartupError("independent_signer_service_config_required")
        self._config = config
        self._owns_transport = transport is None
        if transport is not None:
            self._transport = transport
        else:
            token = os.getenv(config.vault_token_env, "")
            if not isinstance(token, str) or not token:
                raise IndependentSignerStartupError("independent_signer_vault_token_missing")
            self._transport = VaultTransitClient(VaultTransitConfig(
                addr=config.vault_address,
                namespace="",
                token=token,
                mount=config.vault_transit_mount,
                timeout_s=float(config.vault_timeout_seconds),
                cacert="",
                skip_verify=False,
                key_name=config.vault_key_name,
                key_map_path="",
            ))

    @property
    def signer_id(self) -> str:
        return self._config.signer_id

    @property
    def public_key(self) -> str:
        return self._config.signer_public_key

    @property
    def key_version(self) -> int:
        return self._config.signer_key_version

    def close(self) -> None:
        if self._owns_transport:
            close = getattr(self._transport, "close", None)
            if callable(close):
                close()

    def validate_identity(self) -> IndependentSignerVaultIdentity:
        try:
            metadata = self._transport.read_key_metadata(self._config.vault_key_name)
        except Exception as exc:
            raise IndependentSignerVaultError("independent_signer_vault_metadata_unavailable") from exc
        if not isinstance(metadata, Mapping):
            raise IndependentSignerVaultError("independent_signer_vault_metadata_malformed")
        if metadata.get("type") != "ed25519" or metadata.get("disabled") is True or metadata.get("deletion_time"):
            raise IndependentSignerVaultError("independent_signer_vault_key_unavailable")
        if metadata.get("supports_signing") is not True:
            raise IndependentSignerVaultError("independent_signer_vault_key_not_signable")
        keys = metadata.get("keys")
        version = str(self._config.signer_key_version)
        if not isinstance(keys, Mapping) or version not in keys:
            raise IndependentSignerVaultError("independent_signer_vault_key_version_missing")
        try:
            public_key = parse_vault_public_key(keys[version])
        except (TypeError, ValueError) as exc:
            raise IndependentSignerVaultError("independent_signer_vault_public_key_malformed") from exc
        if public_key != self._config.signer_public_key:
            raise IndependentSignerVaultError("independent_signer_vault_public_key_mismatch")
        return IndependentSignerVaultIdentity(
            self._config.signer_id, public_key, self._config.signer_key_version, self._config.vault_key_name,
        )

    def _sign_persisted_record(self, record: IndependentJournalRecord) -> _VaultSignature:
        """Sign only exact P0C2 SIGNING record bytes with the configured key."""
        if record.state != SIGNING or record.binding.signer_id != self.signer_id:
            raise IndependentSignerVaultError("independent_signer_record_not_signable")
        message = record.canonical_message
        digest = hashlib.sha256(message).hexdigest()
        if (len(message) != 235 or message[:18] != b"PROPHET_RESOLVE_V2"
                or digest != record.canonical_message_digest
                or record.binding.signer_public_key != self.public_key
                or record.binding.signer_key_epoch != self.key_version):
            raise IndependentSignerVaultError("independent_signer_persisted_message_invalid")
        try:
            version, signature = self._transport.sign_versioned(
                self._config.vault_key_name, message, key_version=self._config.signer_key_version,
            )
        except Exception as exc:
            raise IndependentSignerVaultError("independent_signer_vault_signing_ambiguous") from exc
        if version != self.key_version:
            raise IndependentSignerVaultError("independent_signer_vault_result_key_version_mismatch")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise IndependentSignerVaultError("independent_signer_vault_signature_malformed")
        try:
            if not Signature.from_bytes(signature).verify(Pubkey.from_string(self.public_key), message):
                raise IndependentSignerVaultError("independent_signer_vault_signature_invalid")
        except IndependentSignerVaultError:
            raise
        except Exception as exc:
            raise IndependentSignerVaultError("independent_signer_vault_signature_malformed") from exc
        return _VaultSignature(self.signer_id, self.public_key, version, digest, signature)


@dataclass(frozen=True)
class IndependentSignerExecutionResult:
    signer_role: str
    signer_id: str
    public_key: str
    key_version: int
    scope_id: str
    settlement_authorization_job_id: str
    canonical_message_digest: str
    operation_id: str
    signature: bytes
    state: str = SIGNED


class IndependentSignerEngine:
    """Execute exactly one locally authorized signer decision at a time."""

    def __init__(
        self,
        *,
        service_config: IndependentSignerServiceConfig,
        authorization_config: SignerAuthorizationConfig,
        journal: IndependentSignerJournal,
        rpc: FinalizedRpc,
        vault: IndependentSignerVaultAdapter,
    ) -> None:
        if not isinstance(service_config, IndependentSignerServiceConfig):
            raise IndependentSignerStartupError("independent_signer_service_config_required")
        if not isinstance(authorization_config, SignerAuthorizationConfig):
            raise IndependentSignerStartupError("independent_signer_authorization_config_required")
        if not isinstance(journal, IndependentSignerJournal):
            raise IndependentSignerStartupError("independent_signer_journal_required")
        if not isinstance(vault, IndependentSignerVaultAdapter):
            raise IndependentSignerStartupError("independent_signer_vault_adapter_required")
        if (
            service_config.signer_role != authorization_config.signer_slot
            or service_config.signer_public_key != authorization_config.own_notary_public_key
            or service_config.expected_genesis_hash != authorization_config.expected_cluster_genesis_hash
            or service_config.expected_program_id != authorization_config.expected_program_id
            or journal.binding.signer_slot != service_config.signer_role
            or journal.binding.signer_id != service_config.signer_id
            or journal.binding.signer_public_key != service_config.signer_public_key
            or journal.binding.signer_key_epoch != service_config.signer_key_version
            or vault.signer_id != service_config.signer_id
            or vault.public_key != service_config.signer_public_key
            or vault.key_version != service_config.signer_key_version
        ):
            raise IndependentSignerStartupError("independent_signer_local_bindings_mismatch")
        self._service_config = service_config
        self._authorization_config = authorization_config
        self._journal = journal
        self._rpc = rpc
        self._vault = vault

    def execute(self, request: Mapping[str, Any], *, now_ms: int) -> IndependentSignerExecutionResult:
        if not isinstance(request, Mapping):
            raise IndependentSignerExecutionError("independent_signer_request_invalid")
        # This is the sole ingress from untrusted input into the signing path.
        carrier = authorize_for_journal(
            request=request,
            config=self._authorization_config,
            rpc=self._rpc,
            now_ms=now_ms,
        )
        record = self._journal.prepare(carrier)
        if record.state == SIGNED:
            return self._result(record)
        if record.state != PREPARED:
            raise IndependentSignerExecutionError("independent_signer_existing_state_not_signable")
        # Metadata validation is intentionally before the durable attempt marker.
        self._vault.validate_identity()
        signing = self._journal.begin_signing(record.scope.scope_id)
        if signing.state == SIGNED:
            return self._result(signing)
        if signing.state != SIGNING:
            raise IndependentSignerExecutionError("independent_signer_begin_signing_invalid")
        signature: bytes | None = None
        try:
            vault_result = self._vault._sign_persisted_record(signing)
            signature = vault_result.signature
            if (
                vault_result.signer_id != self._service_config.signer_id
                or vault_result.public_key != self._service_config.signer_public_key
                or vault_result.key_version != self._service_config.signer_key_version
                or vault_result.canonical_message_digest != signing.canonical_message_digest
            ):
                raise IndependentSignerVaultError("independent_signer_vault_result_binding_mismatch")
            signed = self._journal.record_signature(
                signing.scope.scope_id,
                signature=signature,
                signer_key_epoch=self._service_config.signer_key_version,
            )
            if signed.state != SIGNED:
                raise IndependentSignerExecutionError("independent_signer_signed_state_not_durable")
            return self._result(signed)
        except Exception as exc:
            # A committed signing attempt is always ambiguous unless a matching
            # durable SIGNED row can be observed; never issue another request.
            try:
                current = self._journal.get(signing.scope.scope_id)
                if current.state == SIGNED and signature is not None and current.signature == signature:
                    return self._result(current)
                if current.state == SIGNING:
                    self._journal.mark_uncertain(signing.scope.scope_id, reason="vault_signing_ambiguous")
            except Exception:
                pass
            raise IndependentSignerExecutionError("independent_signer_signing_uncertain") from exc

    def _result(self, record: IndependentJournalRecord) -> IndependentSignerExecutionResult:
        if record.state != SIGNED or record.signature is None or record.operation_id is None:
            raise IndependentSignerExecutionError("independent_signer_signed_record_invalid")
        return IndependentSignerExecutionResult(
            self._service_config.signer_role,
            self._service_config.signer_id,
            self._service_config.signer_public_key,
            self._service_config.signer_key_version,
            record.scope.scope_id,
            record.settlement_authorization_job_id,
            record.canonical_message_digest,
            record.operation_id,
            record.signature,
        )
