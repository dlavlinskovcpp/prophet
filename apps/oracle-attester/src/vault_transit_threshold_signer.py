"""Strict, in-memory 2-of-2 orchestration for pinned Vault Transit signers.

This module deliberately accepts only already-canonical settlement bytes.  It has
no knowledge of Resolver V2 bundles, coordinator state, Solana transactions, or
Vault HTTP details.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from solders.pubkey import Pubkey
from solders.signature import Signature

from .vault_transit_signer_identity import (
    VaultSignerIdentityCollision,
    VaultSignerKeyVersionError,
    VaultSignerSignatureError,
    VaultTransitSignature,
    VaultTransitSignerClient,
    select_signer_epoch,
    validate_signer_pair,
)
from .signing_journal import (
    JournalSignerBinding,
    SigningJournal,
    SigningJournalBindingError,
    SigningJournalIntent,
    SigningJournalStateError,
    settlement_signing_scope,
)


class ThresholdResolutionSignerError(RuntimeError): pass
class ThresholdSignerAFailure(ThresholdResolutionSignerError): pass
class ThresholdSignerBFailure(ThresholdResolutionSignerError): pass
class ThresholdSignerIdentityMismatch(ThresholdResolutionSignerError): pass
class ThresholdSignerMessageMismatch(ThresholdResolutionSignerError): pass
class ThresholdSignerMalformedBundle(ThresholdResolutionSignerError): pass
class ThresholdSignerSignatureInvalid(ThresholdResolutionSignerError): pass


@dataclass(frozen=True)
class ThresholdSignatureBundle:
    """Ordered A-then-B application metadata; not an on-chain wire format."""

    canonical_message_digest: str
    signer_a_id: str
    signer_a_public_key: str
    signer_a_key_version: int
    signer_a_signature: bytes
    signer_b_id: str
    signer_b_public_key: str
    signer_b_key_version: int
    signer_b_signature: bytes


class ThresholdResolutionSigner:
    """Require two fixed, distinct pinned Transit signers for exact same bytes."""

    def __init__(self, *, signer_a: VaultTransitSignerClient, signer_b: VaultTransitSignerClient, journal: SigningJournal | None = None) -> None:
        if signer_a is signer_b:
            raise VaultSignerIdentityCollision("vault_signer_clients_must_be_distinct")
        # Static configuration checks fail before any signing attempt.  Metadata
        # is revalidated in sign_2_of_2 through validate_signer_pair.
        if (
            signer_a.signer.signer_id == signer_b.signer.signer_id
            or signer_a.signer.key_name == signer_b.signer.key_name
            or signer_a.signer.expected_public_key == signer_b.signer.expected_public_key
        ):
            raise VaultSignerIdentityCollision("vault_signer_identities_are_not_distinct")
        self._signer_a = signer_a
        self._signer_b = signer_b
        self._journal = journal

    @property
    def signer_a(self) -> VaultTransitSignerClient:
        return self._signer_a

    @property
    def signer_b(self) -> VaultTransitSignerClient:
        return self._signer_b

    @property
    def journal(self) -> SigningJournal | None:
        return self._journal

    @staticmethod
    def _require_message(message: bytes) -> bytes:
        if not isinstance(message, bytes) or not message:
            raise ThresholdSignerMessageMismatch("canonical_message_is_required")
        return message

    @staticmethod
    def _validate_signature(
        signed: VaultTransitSignature,
        *, signer_id: str,
        public_key: str,
        key_version: int,
        message: bytes,
    ) -> None:
        digest = hashlib.sha256(message).hexdigest()
        if signed.signer_id != signer_id or signed.public_key != public_key:
            raise ThresholdSignerIdentityMismatch("threshold_signer_identity_mismatch")
        if signed.key_version != key_version:
            raise VaultSignerKeyVersionError("threshold_signer_key_version_mismatch")
        if signed.message_digest != digest:
            raise ThresholdSignerMessageMismatch("threshold_signature_message_digest_mismatch")
        if not isinstance(signed.signature, bytes) or len(signed.signature) != 64:
            raise ThresholdSignerMalformedBundle("threshold_signature_malformed")
        try:
            valid = Signature.from_bytes(signed.signature).verify(Pubkey.from_string(public_key), message)
        except Exception as exc:
            raise ThresholdSignerMalformedBundle("threshold_signature_malformed") from exc
        if not valid:
            raise ThresholdSignerSignatureInvalid("threshold_signature_does_not_verify")

    def validate_bundle(self, bundle: ThresholdSignatureBundle, canonical_message: bytes) -> None:
        """Validate an externally carried bundle before it can be consumed later."""
        if self._journal is not None:
            try:
                intent = self._journal.get(settlement_signing_scope(canonical_message))
                signer_a = self._signer_a.for_pinned_epoch(signer_id=intent.signer_a.signer_id, public_key=intent.signer_a.public_key, key_version=intent.signer_a.key_version)
                signer_b = self._signer_b.for_pinned_epoch(signer_id=intent.signer_b.signer_id, public_key=intent.signer_b.public_key, key_version=intent.signer_b.key_version)
                self._validate_bundle_with_clients(bundle, canonical_message, signer_a, signer_b)
                return
            except SigningJournalStateError as exc:
                if str(exc) != "signing_intent_not_found": raise
        self._validate_bundle_with_clients(bundle, canonical_message, self._signer_a, self._signer_b)

    @classmethod
    def _validate_bundle_with_bindings(
        cls,
        bundle: ThresholdSignatureBundle,
        canonical_message: bytes,
        *,
        signer_a_id: str,
        signer_a_public_key: str,
        signer_a_key_version: int,
        signer_b_id: str,
        signer_b_public_key: str,
        signer_b_key_version: int,
    ) -> None:
        message = cls._require_message(canonical_message)
        if not isinstance(bundle, ThresholdSignatureBundle):
            raise ThresholdSignerMalformedBundle("threshold_bundle_malformed")
        digest = hashlib.sha256(message).hexdigest()
        if bundle.canonical_message_digest != digest:
            raise ThresholdSignerMessageMismatch("threshold_bundle_message_digest_mismatch")
        cls._validate_signature(
            VaultTransitSignature(
                bundle.signer_a_id, bundle.signer_a_key_version, bundle.signer_a_public_key,
                bundle.signer_a_signature, digest
            ),
            signer_id=signer_a_id, public_key=signer_a_public_key,
            key_version=signer_a_key_version, message=message,
        )
        cls._validate_signature(
            VaultTransitSignature(
                bundle.signer_b_id, bundle.signer_b_key_version, bundle.signer_b_public_key,
                bundle.signer_b_signature, digest
            ),
            signer_id=signer_b_id, public_key=signer_b_public_key,
            key_version=signer_b_key_version, message=message,
        )

    def _validate_bundle_with_clients(self, bundle: ThresholdSignatureBundle, canonical_message: bytes, signer_a: VaultTransitSignerClient, signer_b: VaultTransitSignerClient) -> None:
        identity_a, identity_b = validate_signer_pair(signer_a, signer_b)
        self._validate_bundle_with_bindings(
            bundle, canonical_message,
            signer_a_id=identity_a.signer_id, signer_a_public_key=identity_a.public_key,
            signer_a_key_version=identity_a.vault_key_version,
            signer_b_id=identity_b.signer_id, signer_b_public_key=identity_b.public_key,
            signer_b_key_version=identity_b.vault_key_version,
        )

    def validate_durable_bundle_offline(
        self, bundle: ThresholdSignatureBundle, canonical_message: bytes
    ) -> None:
        """Validate one durable completed bundle with zero Vault/network calls.

        The signing journal supplies the immutable A/B slots. Configured key epochs
        prove that each persisted signer/version/public-key tuple is an allowed
        historical pin. Ed25519 verification is local. No Vault metadata lookup or
        signing method is invoked.
        """
        if self._journal is None:
            raise ThresholdResolutionSignerError("durable_signing_journal_required_for_validation")
        message = self._require_message(canonical_message)
        try:
            intent = self._journal.get(settlement_signing_scope(message))
            signer_a = self._signer_a.for_pinned_epoch(
                signer_id=intent.signer_a.signer_id, public_key=intent.signer_a.public_key,
                key_version=intent.signer_a.key_version,
            )
            signer_b = self._signer_b.for_pinned_epoch(
                signer_id=intent.signer_b.signer_id, public_key=intent.signer_b.public_key,
                key_version=intent.signer_b.key_version,
            )
        except SigningJournalStateError as exc:
            raise ThresholdSignerMalformedBundle("durable_signing_intent_missing") from exc
        if (
            signer_a.signer.signer_id == signer_b.signer.signer_id
            or signer_a.signer.key_name == signer_b.signer.key_name
            or signer_a.signer.expected_public_key == signer_b.signer.expected_public_key
        ):
            raise ThresholdSignerIdentityMismatch("threshold_signer_identities_not_distinct")
        self._validate_bundle_with_bindings(
            bundle, message,
            signer_a_id=signer_a.signer.signer_id,
            signer_a_public_key=signer_a.signer.expected_public_key,
            signer_a_key_version=signer_a.signer.expected_key_version,
            signer_b_id=signer_b.signer.signer_id,
            signer_b_public_key=signer_b.signer.expected_public_key,
            signer_b_key_version=signer_b.signer.expected_key_version,
        )

    def prepare_2_of_2(
        self, canonical_message: bytes, *, coordinator_job_id: str | None = None, intent_created_at_ms: int | None = None,
    ) -> SigningJournalIntent:
        """Create/load and commit the pinned durable intent without calling Vault."""
        if self._journal is None:
            raise ThresholdResolutionSignerError("durable_signing_journal_required_for_prepare")
        message = self._require_message(canonical_message)
        try:
            existing = self._journal.get(settlement_signing_scope(message))
            signer_a = self._signer_a.for_pinned_epoch(
                signer_id=existing.signer_a.signer_id, public_key=existing.signer_a.public_key, key_version=existing.signer_a.key_version
            )
            signer_b = self._signer_b.for_pinned_epoch(
                signer_id=existing.signer_b.signer_id, public_key=existing.signer_b.public_key, key_version=existing.signer_b.key_version
            )
            created_at_ms = None
        except SigningJournalStateError as exc:
            if str(exc) != "signing_intent_not_found":
                raise
            created_at_ms = int(time.time() * 1000) if intent_created_at_ms is None else intent_created_at_ms
            signer_a = self._signer_a.for_epoch(select_signer_epoch(self._signer_a.signer, created_at_ms))
            signer_b = self._signer_b.for_epoch(select_signer_epoch(self._signer_b.signer, created_at_ms))
        identity_a, identity_b = validate_signer_pair(signer_a, signer_b)
        try:
            return self._journal.reserve_intent(
                message,
                signer_a=JournalSignerBinding(identity_a.signer_id, identity_a.public_key, identity_a.vault_key_version),
                signer_b=JournalSignerBinding(identity_b.signer_id, identity_b.public_key, identity_b.vault_key_version),
                created_at_ms=created_at_ms,
                coordinator_job_id=coordinator_job_id,
            )
        except SigningJournalBindingError as exc:
            # Another caller may have won creation exactly across a key-epoch
            # boundary after our initial read. The durable intent is authoritative:
            # rehydrate its pinned epochs rather than reselecting active/latest.
            if str(exc) != "signing_scope_signer_binding_mismatch":
                raise
            existing = self._journal.get(settlement_signing_scope(message))
            persisted_a = self._signer_a.for_pinned_epoch(
                signer_id=existing.signer_a.signer_id, public_key=existing.signer_a.public_key, key_version=existing.signer_a.key_version
            )
            persisted_b = self._signer_b.for_pinned_epoch(
                signer_id=existing.signer_b.signer_id, public_key=existing.signer_b.public_key, key_version=existing.signer_b.key_version
            )
            persisted_identity_a, persisted_identity_b = validate_signer_pair(persisted_a, persisted_b)
            return self._journal.reserve_intent(
                message,
                signer_a=JournalSignerBinding(
                    persisted_identity_a.signer_id, persisted_identity_a.public_key, persisted_identity_a.vault_key_version
                ),
                signer_b=JournalSignerBinding(
                    persisted_identity_b.signer_id, persisted_identity_b.public_key, persisted_identity_b.vault_key_version
                ),
                coordinator_job_id=coordinator_job_id,
            )

    def sign_2_of_2(
        self, canonical_message: bytes, *, intent_created_at_ms: int | None = None, coordinator_job_id: str | None = None,
    ) -> ThresholdSignatureBundle:
        """Sign once sequentially (A then B); no retries and no partial success."""
        message = self._require_message(canonical_message)
        signer_a, signer_b = self._signer_a, self._signer_b
        signing_scope_id = None
        persisted_a = persisted_b = None
        if self._journal is not None:
            intent = self.prepare_2_of_2(
                message, coordinator_job_id=coordinator_job_id, intent_created_at_ms=intent_created_at_ms
            )
            signer_a = self._signer_a.for_pinned_epoch(
                signer_id=intent.signer_a.signer_id, public_key=intent.signer_a.public_key, key_version=intent.signer_a.key_version
            )
            signer_b = self._signer_b.for_pinned_epoch(
                signer_id=intent.signer_b.signer_id, public_key=intent.signer_b.public_key, key_version=intent.signer_b.key_version
            )
            identity_a, identity_b = validate_signer_pair(signer_a, signer_b)
            signing_scope_id = intent.signing_scope_id
            persisted_a = self._journal.begin_signer(signing_scope_id, "A")
        else:
            identity_a, identity_b = validate_signer_pair(signer_a, signer_b)
        try:
            signed_a = persisted_a or signer_a.sign_canonical_message(message)
            self._validate_signature(signed_a, signer_id=identity_a.signer_id, public_key=identity_a.public_key, key_version=identity_a.vault_key_version, message=message)
        except ThresholdResolutionSignerError:
            raise
        except Exception as exc:
            raise ThresholdSignerAFailure("threshold_signer_a_failed") from exc
        if self._journal is not None and persisted_a is None:
            self._journal.record_signature(signing_scope_id, "A", signed_a)
        if self._journal is not None:
            persisted_b = self._journal.begin_signer(signing_scope_id, "B")
        try:
            signed_b = persisted_b or signer_b.sign_canonical_message(message)
            self._validate_signature(signed_b, signer_id=identity_b.signer_id, public_key=identity_b.public_key, key_version=identity_b.vault_key_version, message=message)
        except ThresholdResolutionSignerError:
            raise
        except Exception as exc:
            raise ThresholdSignerBFailure("threshold_signer_b_failed") from exc
        if self._journal is not None and persisted_b is None:
            self._journal.record_signature(signing_scope_id, "B", signed_b)
        bundle = ThresholdSignatureBundle(
            canonical_message_digest=hashlib.sha256(message).hexdigest(),
            signer_a_id=signed_a.signer_id, signer_a_public_key=signed_a.public_key,
            signer_a_key_version=signed_a.key_version, signer_a_signature=signed_a.signature,
            signer_b_id=signed_b.signer_id, signer_b_public_key=signed_b.public_key,
            signer_b_key_version=signed_b.key_version, signer_b_signature=signed_b.signature,
        )
        self._validate_bundle_with_clients(bundle, message, signer_a, signer_b)
        return bundle

    def resume_2_of_2(self, canonical_message: bytes) -> ThresholdSignatureBundle:
        """Explicit exact-message recovery entrypoint; it never broadens retries.

        With a journal, durable completed signatures are reused, an A-durable/B-
        not-started record can continue sequentially, and uncertain records are
        rejected by the journal before another Vault request. Without a journal
        this method is deliberately unavailable.
        """
        if self._journal is None:
            raise ThresholdResolutionSignerError("durable_signing_journal_required_for_recovery")
        return self.sign_2_of_2(canonical_message)
