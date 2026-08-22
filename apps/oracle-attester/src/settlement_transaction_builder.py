"""Deterministic, network-free Prophet settlement transaction construction.

Phase 6D1 stops at an unsigned MessageV0 artifact. It consumes only durable
AGREED coordinator state plus a completed durable 2/2 signing intent. The only
caller-controlled fields are the transaction fee-payer public key and recent
blockhash; no RPC, Vault, verifier, signing, or submission operation exists here.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Optional

from solders.hash import Hash
from solders.instruction import Instruction
from solders.message import MessageV0
from solders.pubkey import Pubkey

from prophet_sdk.ed25519 import build_ed25519_ix
from prophet_sdk.pdas import derive_market_pda

from .agreed_settlement_signer import (
    AgreedSettlementSigner,
    CoordinatorSigningBindingError,
    canonical_message_for_agreed_job,
)
from .resolution_coordinator_store import (
    AGREED,
    CoordinatorRejected,
    ResolutionCoordinatorStore,
)
from .runtime_config import SolanaRuntimeConfig
from .runtime_clock import wall_clock_ms
from .signing_journal import (
    BOTH_SIGNED,
    SigningJournal,
    SigningJournalError,
)
from .solana_settlement_instructions import build_resolve_threshold_instruction
from .vault_transit_threshold_signer import (
    ThresholdResolutionSigner,
    ThresholdResolutionSignerError,
    ThresholdSignatureBundle,
)


_OUTCOME_INDEX = {"YES": 1, "NO": 2, "INVALID": 3}


class SettlementTransactionConstructionError(RuntimeError):
    """Base class for safe Phase 6D1 construction failures."""


class SettlementTransactionJobError(SettlementTransactionConstructionError):
    pass


class SettlementTransactionBindingError(SettlementTransactionConstructionError):
    pass


class SettlementTransactionSigningStateError(SettlementTransactionConstructionError):
    pass


class SettlementTransactionInputError(SettlementTransactionConstructionError):
    pass


@dataclass(frozen=True)
class SettlementTransactionInput:
    """Minimal construction input; protocol-significant settlement data is absent."""

    coordinator_job_id: str
    signing_intent_id: str
    fee_payer_pubkey: str
    recent_blockhash: str

    def __post_init__(self) -> None:
        if not isinstance(self.coordinator_job_id, str) or not self.coordinator_job_id:
            raise SettlementTransactionInputError("coordinator_job_id_invalid")
        if not isinstance(self.signing_intent_id, str) or not self.signing_intent_id:
            raise SettlementTransactionInputError("signing_intent_id_invalid")
        try:
            if str(Pubkey.from_string(self.fee_payer_pubkey)) != self.fee_payer_pubkey:
                raise ValueError
        except Exception as exc:
            raise SettlementTransactionInputError("fee_payer_pubkey_invalid") from exc
        try:
            if str(Hash.from_string(self.recent_blockhash)) != self.recent_blockhash:
                raise ValueError
        except Exception as exc:
            raise SettlementTransactionInputError("recent_blockhash_invalid") from exc


@dataclass(frozen=True)
class SettlementTransactionArtifact:
    """Immutable unsigned settlement transaction-message artifact."""

    coordinator_job_id: str
    signing_intent_id: str
    program_id: str
    cluster: str
    genesis_hash: str
    fee_payer_pubkey: str
    recent_blockhash: str
    canonical_message_digest: str
    canonical_message: bytes
    signer_a_id: str
    signer_a_public_key: str
    signer_a_key_version: int
    signer_a_signature: bytes
    signer_b_id: str
    signer_b_public_key: str
    signer_b_key_version: int
    signer_b_signature: bytes
    instructions: tuple[Instruction, Instruction, Instruction]
    message: MessageV0
    serialized_message: bytes
    message_digest: str


class SettlementTransactionBuilder:
    """Read-only bridge from durable settlement evidence to unsigned MessageV0."""

    def __init__(
        self,
        *,
        coordinator_state: ResolutionCoordinatorStore,
        signing_journal: SigningJournal,
        threshold_signer: ThresholdResolutionSigner,
        solana_runtime: SolanaRuntimeConfig,
        clock_ms: Optional[Callable[[], int]] = None,
    ) -> None:
        if not isinstance(solana_runtime, SolanaRuntimeConfig):
            raise SettlementTransactionBindingError("validated_solana_runtime_required")
        try:
            program_id = Pubkey.from_string(solana_runtime.prophet_program_id)
            genesis_hash = Hash.from_string(solana_runtime.genesis_hash)
        except Exception as exc:
            raise SettlementTransactionBindingError("solana_runtime_identity_invalid") from exc
        if not solana_runtime.cluster:
            raise SettlementTransactionBindingError("solana_runtime_cluster_invalid")
        if not isinstance(threshold_signer, ThresholdResolutionSigner):
            raise SettlementTransactionBindingError("threshold_signer_validation_boundary_required")
        if threshold_signer.journal is not signing_journal:
            raise SettlementTransactionBindingError("threshold_signer_journal_mismatch")
        self._coordinator_state = coordinator_state
        self._journal = signing_journal
        self._threshold_signer = threshold_signer
        self._runtime = solana_runtime
        self._program_id = program_id
        self._genesis_hash = genesis_hash
        if clock_ms is not None and not callable(clock_ms):
            raise SettlementTransactionBindingError("settlement_transaction_clock_invalid")
        self._clock_ms = clock_ms or wall_clock_ms

    def build(self, request: SettlementTransactionInput) -> SettlementTransactionArtifact:
        if not isinstance(request, SettlementTransactionInput):
            raise SettlementTransactionInputError("settlement_transaction_input_invalid")

        job = self._load_agreed_job(request.coordinator_job_id)
        context, runtime_binding = self._load_runtime_bound_context(job.job_id)
        self._validate_program_and_market(job, context, runtime_binding)
        intent = self._load_completed_intent(job.job_id, request.signing_intent_id)

        # Durable journal bytes are the authoritative bytes given to Ed25519. We
        # derive through the existing serializer only as an equality assertion.
        canonical_message = intent.canonical_message
        try:
            expected_message = canonical_message_for_agreed_job(self._coordinator_state, job)
        except CoordinatorSigningBindingError as exc:
            raise SettlementTransactionBindingError("canonical_settlement_binding_invalid") from exc
        digest = hashlib.sha256(canonical_message).hexdigest()
        if canonical_message != expected_message:
            raise SettlementTransactionBindingError("durable_canonical_message_mismatch")
        if intent.canonical_message_digest != digest:
            raise SettlementTransactionBindingError("durable_canonical_digest_mismatch")

        signed_a, signed_b = intent.signer_a_result, intent.signer_b_result
        if signed_a is None or signed_b is None or intent.state != BOTH_SIGNED:
            raise SettlementTransactionSigningStateError("completed_2of2_bundle_required")

        durable_bundle = ThresholdSignatureBundle(
            canonical_message_digest=intent.canonical_message_digest,
            signer_a_id=intent.signer_a.signer_id,
            signer_a_public_key=intent.signer_a.public_key,
            signer_a_key_version=intent.signer_a.key_version,
            signer_a_signature=signed_a.signature,
            signer_b_id=intent.signer_b.signer_id,
            signer_b_public_key=intent.signer_b.public_key,
            signer_b_key_version=intent.signer_b.key_version,
            signer_b_signature=signed_b.signature,
        )
        try:
            # Existing 2/2 offline validator rehydrates the intent's pinned epochs and
            # checks role, public key, key version, digest, and Ed25519 validity
            # without Vault metadata/signing/network operations.
            self._threshold_signer.validate_durable_bundle_offline(durable_bundle, canonical_message)
        except ThresholdResolutionSignerError as exc:
            raise SettlementTransactionSigningStateError("completed_2of2_bundle_invalid") from exc
        except Exception as exc:
            # Rotation/pinned-epoch validation raises typed signer errors from
            # the existing Vault compatibility layer; construction stays fail-closed.
            raise SettlementTransactionSigningStateError("completed_2of2_bundle_invalid") from exc

        # Fee payer is transaction lifecycle identity only. Resolution authorization
        # remains exclusively the already-durable A/B Ed25519 bundle; no fee-payer
        # key material or signature is accepted by this Phase 6D1 boundary.
        fee_payer = Pubkey.from_string(request.fee_payer_pubkey)

        ed25519_a = build_ed25519_ix(
            canonical_message, signed_a.signature, bytes(Pubkey.from_string(intent.signer_a.public_key))
        )
        ed25519_b = build_ed25519_ix(
            canonical_message, signed_b.signature, bytes(Pubkey.from_string(intent.signer_b.public_key))
        )
        market = Pubkey.from_bytes(bytes.fromhex(job.market))
        notary_config = Pubkey.from_string(context.notary_config)
        resolve_ix = build_resolve_threshold_instruction(
            program_id=self._program_id,
            market=market,
            notary_config=notary_config,
            outcome_idx=_OUTCOME_INDEX[job.outcome],
            proof_hash=bytes.fromhex(context.proof_hash),
            public_inputs_hash=bytes.fromhex(context.public_inputs_hash),
        )
        instructions = (ed25519_a, ed25519_b, resolve_ix)

        recent_blockhash = Hash.from_string(request.recent_blockhash)
        message = MessageV0.try_compile(
            payer=fee_payer,
            instructions=list(instructions),
            address_lookup_table_accounts=[],
            recent_blockhash=recent_blockhash,
        )
        serialized_message = bytes(message)

        return SettlementTransactionArtifact(
            coordinator_job_id=job.job_id,
            signing_intent_id=intent.signing_scope_id,
            program_id=str(self._program_id),
            cluster=self._runtime.cluster,
            genesis_hash=str(self._genesis_hash),
            fee_payer_pubkey=str(fee_payer),
            recent_blockhash=str(recent_blockhash),
            canonical_message_digest=digest,
            canonical_message=canonical_message,
            signer_a_id=intent.signer_a.signer_id,
            signer_a_public_key=intent.signer_a.public_key,
            signer_a_key_version=intent.signer_a.key_version,
            signer_a_signature=signed_a.signature,
            signer_b_id=intent.signer_b.signer_id,
            signer_b_public_key=intent.signer_b.public_key,
            signer_b_key_version=intent.signer_b.key_version,
            signer_b_signature=signed_b.signature,
            instructions=instructions,
            message=message,
            serialized_message=serialized_message,
            message_digest=hashlib.sha256(serialized_message).hexdigest(),
        )

    def _load_agreed_job(self, job_id: str):
        try:
            job = self._coordinator_state.get_job(job_id)
        except CoordinatorRejected as exc:
            raise SettlementTransactionJobError("coordinator_job_missing") from exc
        if job.state != AGREED:
            raise SettlementTransactionJobError("coordinator_job_not_agreed")
        try:
            AgreedSettlementSigner._validate_agreed_binding(job, now_ms=self._clock_ms())
        except CoordinatorSigningBindingError as exc:
            raise SettlementTransactionBindingError("coordinator_agreed_history_invalid") from exc
        return job

    def _load_runtime_bound_context(self, job_id: str):
        try:
            context = self._coordinator_state.get_settlement_context(job_id)
            runtime_binding = self._coordinator_state.get_settlement_runtime(job_id)
        except CoordinatorRejected as exc:
            raise SettlementTransactionBindingError("durable_settlement_binding_missing_or_invalid") from exc
        expected = (
            self._runtime.cluster,
            self._runtime.genesis_hash,
            self._runtime.prophet_program_id,
        )
        actual = (runtime_binding.cluster, runtime_binding.genesis_hash, runtime_binding.program_id)
        if actual != expected:
            raise SettlementTransactionBindingError("solana_runtime_binding_mismatch")
        if context.program_id != self._runtime.prophet_program_id:
            raise SettlementTransactionBindingError("settlement_program_id_mismatch")
        return context, runtime_binding

    def _load_completed_intent(self, job_id: str, signing_intent_id: str):
        try:
            link = self._journal.get_coordinator_link(job_id)
        except SigningJournalError as exc:
            raise SettlementTransactionBindingError("coordinator_signing_link_missing") from exc
        if link.signing_scope_id != signing_intent_id:
            raise SettlementTransactionBindingError("coordinator_signing_intent_mismatch")
        try:
            intent = self._journal.validate_completed_intent(signing_intent_id)
        except SigningJournalError as exc:
            raise SettlementTransactionSigningStateError("completed_2of2_signing_intent_required") from exc
        if link.canonical_message_digest != intent.canonical_message_digest:
            raise SettlementTransactionBindingError("coordinator_signing_digest_mismatch")
        return intent

    def _validate_program_and_market(self, job, context, runtime_binding) -> None:
        if runtime_binding.program_id != context.program_id or context.program_id != str(self._program_id):
            raise SettlementTransactionBindingError("settlement_program_id_mismatch")
        try:
            market = Pubkey.from_bytes(bytes.fromhex(job.market))
            expected_market, _ = derive_market_pda(
                Pubkey.from_string(context.creator),
                bytes.fromhex(job.resolver_definition_hash),
                context.open_ts,
                context.market_nonce,
                self._program_id,
            )
        except Exception as exc:
            raise SettlementTransactionBindingError("market_pda_binding_invalid") from exc
        if market != expected_market:
            raise SettlementTransactionBindingError("market_pda_binding_mismatch")
        if job.outcome not in _OUTCOME_INDEX:
            raise SettlementTransactionBindingError("settlement_outcome_invalid")
