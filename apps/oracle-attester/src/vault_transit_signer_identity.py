"""Metadata-only, pinned Vault Transit signer identity validation for Phase 6C1."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping, Optional

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature

from .runtime_config import ResolverRuntimeConfig, VaultSignerConfig, VaultSignerKeyEpoch, VaultSigningConfig
from .vault_transit import VaultTransitClient, VaultTransitConfig, VaultTransitError, parse_vault_public_key


class VaultSignerError(RuntimeError): pass
class VaultSignerConfigurationError(VaultSignerError): pass
class VaultSignerAuthenticationError(VaultSignerError): pass
class VaultSignerTransportError(VaultSignerError): pass
class VaultSignerPermissionError(VaultSignerError): pass
class VaultSignerKeyMissingError(VaultSignerError): pass
class VaultSignerKeyTypeError(VaultSignerError): pass
class VaultSignerKeyVersionError(VaultSignerError): pass
class VaultSignerPublicKeyMismatch(VaultSignerError): pass
class VaultSignerMetadataError(VaultSignerError): pass
class VaultSignerIdentityCollision(VaultSignerError): pass
class VaultSignerSignatureError(VaultSignerError): pass
class VaultSignerSignatureVerificationError(VaultSignerError): pass
class VaultSignerRotationError(VaultSignerError): pass


def select_signer_epoch(signer: VaultSignerConfig, intent_created_at_ms: int) -> VaultSignerKeyEpoch:
    """Select one explicit epoch: activation inclusive, retirement exclusive."""
    if isinstance(intent_created_at_ms, bool) or not isinstance(intent_created_at_ms, int) or intent_created_at_ms < 0:
        raise VaultSignerRotationError("signing_intent_creation_time_invalid")
    active = [epoch for epoch in signer.key_epochs if epoch.activation_time_ms <= intent_created_at_ms and (epoch.retirement_time_ms is None or intent_created_at_ms < epoch.retirement_time_ms)]
    if len(active) != 1:
        raise VaultSignerRotationError("no_unique_signer_key_epoch_for_intent")
    return active[0]


@dataclass(frozen=True)
class VaultTransitSignerIdentity:
    signer_id: str
    vault_key_name: str
    vault_key_version: int
    public_key: str
    key_type: str
    config_fingerprint: str
    public_key_fingerprint: str


@dataclass(frozen=True)
class VaultTransitSignature:
    signer_id: str
    key_version: int
    public_key: str
    signature: bytes
    message_digest: str


class DeterministicTestVaultTransit:
    """Explicit test-only metadata transport; it intentionally has no signing API."""

    def __init__(self, metadata_by_key: Mapping[str, Mapping[str, Any]], *, signers_by_key: Optional[Mapping[str, Keypair]] = None, reported_versions: Optional[Mapping[str, int]] = None):
        self._metadata = MappingProxyType({key: MappingProxyType(dict(value)) for key, value in metadata_by_key.items()})
        self._signers = MappingProxyType(dict(signers_by_key or {}))
        self._reported_versions = MappingProxyType(dict(reported_versions or {}))

    def read_key_metadata(self, key_name: str) -> dict[str, Any]:
        if key_name not in self._metadata:
            raise VaultTransitError("test key not found", status_code=404)
        return dict(self._metadata[key_name])

    def sign_versioned(self, key_name: str, message: bytes, *, key_version: Optional[int]) -> tuple[int, bytes]:
        signer = self._signers.get((key_name, key_version), self._signers.get(key_name))
        if signer is None:
            raise VaultTransitError("test signing key not found", status_code=404)
        if key_version is None:
            raise VaultTransitError("test signing requires an explicit key version")
        return self._reported_versions.get(key_name, key_version), bytes(signer.sign_message(message))


class VaultTransitSignerClient:
    """One immutable signer/key binding. This class deliberately cannot sign."""

    def __init__(
        self,
        *,
        signing: VaultSigningConfig,
        signer: VaultSignerConfig,
        config_fingerprint: str,
        vault_token: str,
        transport: Optional[Any] = None,
    ) -> None:
        if not vault_token:
            raise VaultSignerAuthenticationError("missing_vault_token")
        self.signing = signing
        self.signer = signer
        self._config_fingerprint = config_fingerprint
        self._vault_token = vault_token
        self._owns_transport = transport is None
        if signing.backend == "deterministic-test":
            if transport is None:
                raise VaultSignerConfigurationError("test_vault_transport_must_be_explicit")
            self._transport = transport
        else:
            self._transport = transport or VaultTransitClient(VaultTransitConfig(
                addr=signing.address,
                namespace="",
                token=vault_token,
                mount=signing.transit_mount,
                timeout_s=float(signing.request_timeout_seconds),
                cacert="",
                skip_verify=False,
                key_name="",
                key_map_path="",
            ))

    @classmethod
    def from_runtime(
        cls,
        runtime_config: ResolverRuntimeConfig,
        *,
        slot: str,
        transport: Optional[Any] = None,
    ) -> "VaultTransitSignerClient":
        if runtime_config.signing is None:
            raise VaultSignerConfigurationError("vault_signing_configuration_missing")
        if slot == "A":
            signer = runtime_config.signing.signer_a
        elif slot == "B":
            signer = runtime_config.signing.signer_b
        else:
            raise VaultSignerConfigurationError("unsupported_signer_slot")
        token = os.getenv(runtime_config.signing.token_env, "")
        if not token:
            raise VaultSignerAuthenticationError("missing_vault_token")
        return cls(signing=runtime_config.signing, signer=signer, config_fingerprint=runtime_config.fingerprint(), vault_token=token, transport=transport)

    def close(self) -> None:
        if self._owns_transport:
            close = getattr(self._transport, "close", None)
            if close is not None:
                close()

    def for_epoch(self, epoch: VaultSignerKeyEpoch) -> "VaultTransitSignerClient":
        """Bind a new client view to a configured epoch; it never selects latest."""
        if epoch not in self.signer.key_epochs:
            raise VaultSignerRotationError("signer_epoch_not_in_configured_policy")
        pinned = replace(self.signer, expected_public_key=epoch.public_key, expected_key_version=epoch.key_version)
        return VaultTransitSignerClient(signing=self.signing, signer=pinned, config_fingerprint=self._config_fingerprint, vault_token=self._vault_token, transport=self._transport)
    def for_pinned_epoch(self, *, signer_id: str, public_key: str, key_version: int) -> "VaultTransitSignerClient":
        if signer_id != self.signer.signer_id:
            raise VaultSignerRotationError("signing_intent_signer_identity_mismatch")
        matches = [epoch for epoch in self.signer.key_epochs if epoch.key_version == key_version and epoch.public_key == public_key]
        if len(matches) != 1:
            raise VaultSignerRotationError("historical_signer_key_epoch_unavailable")
        return self.for_epoch(matches[0])

    def validate_identity(self) -> VaultTransitSignerIdentity:
        try:
            metadata = self._transport.read_key_metadata(self.signer.key_name)
        except VaultTransitError as exc:
            if exc.status_code == 401:
                raise VaultSignerAuthenticationError("vault_authentication_rejected") from exc
            if exc.status_code == 403:
                raise VaultSignerPermissionError("vault_permission_denied") from exc
            if exc.status_code == 404:
                raise VaultSignerKeyMissingError("vault_transit_key_missing") from exc
            raise VaultSignerTransportError("vault_metadata_unavailable") from exc
        except Exception as exc:
            raise VaultSignerTransportError("vault_metadata_unavailable") from exc
        if not isinstance(metadata, Mapping):
            raise VaultSignerMetadataError("vault_key_metadata_malformed")
        if metadata.get("type") != "ed25519":
            raise VaultSignerKeyTypeError("vault_key_type_is_not_ed25519")
        if metadata.get("disabled") is True or metadata.get("deletion_time"):
            raise VaultSignerMetadataError("vault_key_is_unavailable")
        if metadata.get("supports_signing") is False:
            raise VaultSignerMetadataError("vault_key_does_not_support_signing")
        keys = metadata.get("keys")
        version = str(self.signer.expected_key_version)
        if not isinstance(keys, Mapping) or version not in keys:
            raise VaultSignerKeyVersionError("expected_vault_key_version_missing")
        try:
            public_key = parse_vault_public_key(keys[version])
        except (TypeError, ValueError) as exc:
            raise VaultSignerMetadataError("vault_public_key_malformed") from exc
        if public_key != self.signer.expected_public_key:
            raise VaultSignerPublicKeyMismatch("vault_public_key_does_not_match_pin")
        return VaultTransitSignerIdentity(
            signer_id=self.signer.signer_id,
            vault_key_name=self.signer.key_name,
            vault_key_version=self.signer.expected_key_version,
            public_key=public_key,
            key_type="ed25519",
            config_fingerprint=self._config_fingerprint,
            public_key_fingerprint=hashlib.sha256(public_key.encode("ascii")).hexdigest(),
        )

    def sign_canonical_message(self, message: bytes) -> VaultTransitSignature:
        """Sign exact caller-supplied canonical bytes with this pinned Transit key only."""
        if not isinstance(message, bytes) or not message:
            raise VaultSignerSignatureError("canonical_message_is_required")
        identity = self.validate_identity()
        try:
            version, signature_bytes = self._transport.sign_versioned(
                self.signer.key_name,
                message,
                key_version=self.signer.expected_key_version,
            )
        except VaultTransitError as exc:
            if exc.status_code == 401:
                raise VaultSignerAuthenticationError("vault_signing_authentication_rejected") from exc
            if exc.status_code == 403:
                raise VaultSignerPermissionError("vault_signing_permission_denied") from exc
            raise VaultSignerSignatureError("vault_signing_unavailable") from exc
        except Exception as exc:
            raise VaultSignerSignatureError("vault_signing_unavailable") from exc
        if version != self.signer.expected_key_version:
            raise VaultSignerKeyVersionError("vault_signature_key_version_mismatch")
        if not isinstance(signature_bytes, bytes) or len(signature_bytes) != 64:
            raise VaultSignerSignatureError("vault_signature_malformed")
        try:
            signature = Signature.from_bytes(signature_bytes)
            if not signature.verify(Pubkey.from_string(identity.public_key), message):
                raise VaultSignerSignatureVerificationError("vault_signature_does_not_verify")
        except VaultSignerSignatureVerificationError:
            raise
        except Exception as exc:
            raise VaultSignerSignatureError("vault_signature_malformed") from exc
        return VaultTransitSignature(
            signer_id=identity.signer_id,
            key_version=version,
            public_key=identity.public_key,
            signature=signature_bytes,
            message_digest=hashlib.sha256(message).hexdigest(),
        )


def validate_signer_pair(
    signer_a: VaultTransitSignerClient,
    signer_b: VaultTransitSignerClient,
) -> tuple[VaultTransitSignerIdentity, VaultTransitSignerIdentity]:
    """Validate both public identities without creating any signing capability."""
    identity_a, identity_b = signer_a.validate_identity(), signer_b.validate_identity()
    if (
        identity_a.signer_id == identity_b.signer_id
        or identity_a.vault_key_name == identity_b.vault_key_name
        or identity_a.public_key == identity_b.public_key
    ):
        raise VaultSignerIdentityCollision("vault_signer_identities_are_not_distinct")
    return identity_a, identity_b
