"""Public-key-only validation boundary for signatures returned by external roles.

The coordinator uses this object instead of a Vault client.  It owns only the
immutable A/B public bindings and the durable journal; signing remains outside
the process.
"""
from __future__ import annotations

import hashlib
from typing import Any

from solders.pubkey import Pubkey
from solders.signature import Signature

from .signing_journal import (
    JournalSignerBinding,
    SigningJournal,
    SigningJournalBindingError,
    SigningJournalError,
    SigningJournalIntent,
    settlement_signing_scope,
)
from .vault_transit_threshold_signer import ThresholdSignatureBundle


class ExternalThresholdValidatorError(RuntimeError):
    pass


class ExternalThresholdBundleValidator:
    """Reserve and validate one exact fixed-role A+B bundle without credentials."""

    supports_settlement_transaction_validation = True

    def __init__(self, *, journal: SigningJournal, signer_a: Any, signer_b: Any) -> None:
        if not isinstance(journal, SigningJournal):
            raise ExternalThresholdValidatorError("external_signing_journal_required")
        self.journal = journal
        self.signer_a = signer_a
        self.signer_b = signer_b
        self._a = JournalSignerBinding(signer_a.signer_id, signer_a.public_key, signer_a.key_version)
        self._b = JournalSignerBinding(signer_b.signer_id, signer_b.public_key, signer_b.key_version)
        if self._a.signer_id == self._b.signer_id or self._a.public_key == self._b.public_key:
            raise ExternalThresholdValidatorError("external_signer_bindings_not_distinct")

    def prepare_2_of_2(self, canonical_message: bytes, *, coordinator_job_id: str | None = None, intent_created_at_ms: int | None = None) -> SigningJournalIntent:
        del intent_created_at_ms
        return self.journal.reserve_intent(canonical_message, signer_a=self._a, signer_b=self._b, coordinator_job_id=coordinator_job_id)

    def validate_durable_bundle_offline(self, bundle: ThresholdSignatureBundle, canonical_message: bytes) -> None:
        if not isinstance(bundle, ThresholdSignatureBundle) or not isinstance(canonical_message, bytes):
            raise ExternalThresholdValidatorError("external_bundle_invalid")
        try:
            intent = self.journal.get(settlement_signing_scope(canonical_message))
            if intent.signer_a != self._a or intent.signer_b != self._b:
                raise ExternalThresholdValidatorError("external_bundle_binding_mismatch")
            digest = hashlib.sha256(canonical_message).hexdigest()
            if bundle.canonical_message_digest != digest:
                raise ExternalThresholdValidatorError("external_bundle_digest_mismatch")
            self._validate(bundle.signer_a_id, bundle.signer_a_public_key, bundle.signer_a_key_version, bundle.signer_a_signature, self._a, canonical_message)
            self._validate(bundle.signer_b_id, bundle.signer_b_public_key, bundle.signer_b_key_version, bundle.signer_b_signature, self._b, canonical_message)
        except ExternalThresholdValidatorError:
            raise
        except (SigningJournalError, ValueError, TypeError) as exc:
            raise ExternalThresholdValidatorError("external_bundle_invalid") from exc

    @staticmethod
    def _validate(signer_id: str, public_key: str, key_version: int, signature: bytes, expected: JournalSignerBinding, message: bytes) -> None:
        if (signer_id, public_key, key_version) != (expected.signer_id, expected.public_key, expected.key_version) or not isinstance(signature, bytes) or len(signature) != 64:
            raise ExternalThresholdValidatorError("external_bundle_identity_or_shape_invalid")
        try:
            if not Signature.from_bytes(signature).verify(Pubkey.from_string(public_key), message):
                raise ExternalThresholdValidatorError("external_bundle_signature_invalid")
        except ExternalThresholdValidatorError:
            raise
        except Exception as exc:
            raise ExternalThresholdValidatorError("external_bundle_signature_invalid") from exc
