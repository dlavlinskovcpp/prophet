"""Phase 6D2: trusted blockhash acquisition, fee-payer signing, and simulation.

This layer deliberately stops before Solana transaction submission.  It reuses the
Phase 6D1 deterministic builder, signs only the transaction envelope with a dedicated
fee payer, and simulates the exact resulting bytes through one genesis-validated RPC.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Mapping, Protocol

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from .runtime_config import (
    ResolverRuntimeConfig,
    SettlementExecutionRuntimeConfig,
    SolanaRuntimeConfig,
)
from .settlement_fee_payer import FilesystemFeePayerSigner, SettlementFeePayerError
from .settlement_rpc import (
    RpcSimulationResult,
    SettlementRpcError,
    SolanaSettlementRpcClient,
)
from .settlement_transaction_builder import (
    SettlementTransactionArtifact,
    SettlementTransactionBuilder,
    SettlementTransactionInput,
)


READY_CANDIDATE = "READY_CANDIDATE"
PROGRAM_REJECTED = "PROGRAM_REJECTED"
STALE_BLOCKHASH = "STALE_BLOCKHASH"


class SettlementSimulationError(RuntimeError):
    pass


class SettlementExecutionConfigError(SettlementSimulationError):
    pass


class SettlementExecutionBindingError(SettlementSimulationError):
    pass


class SettlementExecutionSigningError(SettlementSimulationError):
    pass


class SettlementExecutionRpcError(SettlementSimulationError):
    pass


@dataclass(frozen=True)
class SettlementSimulationRequest:
    coordinator_job_id: str
    signing_intent_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.coordinator_job_id, str) or not self.coordinator_job_id:
            raise SettlementExecutionBindingError("coordinator_job_id_invalid")
        if not isinstance(self.signing_intent_id, str) or not self.signing_intent_id:
            raise SettlementExecutionBindingError("signing_intent_id_invalid")


@dataclass(frozen=True)
class SignedSettlementTransactionArtifact:
    coordinator_job_id: str
    signing_intent_id: str
    program_id: str
    cluster: str
    genesis_hash: str
    fee_payer_pubkey: str
    recent_blockhash: str
    canonical_message_digest: str
    canonical_message: bytes
    signer_a_public_key: str
    signer_a_signature: bytes
    signer_b_public_key: str
    signer_b_signature: bytes
    unsigned: SettlementTransactionArtifact
    transaction: VersionedTransaction
    serialized_transaction: bytes
    transaction_signatures: tuple[str, ...]
    transaction_digest: str


@dataclass(frozen=True)
class SettlementSimulationResult:
    status: str
    ready_for_submission: bool
    transaction: SignedSettlementTransactionArtifact
    program_error: str | None
    logs: tuple[str, ...]
    units_consumed: int | None
    replacement_blockhash: str | None
    replacement_last_valid_block_height: int | None


class _FeePayerSigner(Protocol):
    @property
    def public_key(self) -> Pubkey: ...

    def sign_transaction_message(self, message) -> VersionedTransaction: ...


class _SettlementRpc(Protocol):
    is_test_transport: bool

    def get_genesis_hash(self) -> str: ...

    def get_latest_blockhash(self) -> str: ...

    def simulate_transaction(self, transaction: VersionedTransaction) -> RpcSimulationResult: ...


class SettlementSimulationService:
    """Explicit read-only execution candidate boundary for one completed settlement."""

    def __init__(
        self,
        *,
        builder: SettlementTransactionBuilder,
        solana_runtime: SolanaRuntimeConfig,
        execution_config: SettlementExecutionRuntimeConfig,
        fee_payer_signer: _FeePayerSigner,
        rpc: _SettlementRpc,
        environment: str,
        mode: str,
    ) -> None:
        if not isinstance(builder, SettlementTransactionBuilder):
            raise SettlementExecutionConfigError("settlement_transaction_builder_required")
        if not isinstance(solana_runtime, SolanaRuntimeConfig):
            raise SettlementExecutionConfigError("validated_solana_runtime_required")
        if not isinstance(execution_config, SettlementExecutionRuntimeConfig):
            raise SettlementExecutionConfigError("settlement_execution_config_required")
        if environment == "mainnet":
            raise SettlementExecutionConfigError("mainnet_settlement_execution_not_supported")
        if mode not in {"production", "test"}:
            raise SettlementExecutionConfigError("settlement_execution_mode_invalid")
        if (
            execution_config.expected_cluster != solana_runtime.cluster
            or execution_config.expected_genesis_hash != solana_runtime.genesis_hash
        ):
            raise SettlementExecutionConfigError("settlement_execution_runtime_identity_mismatch")
        if mode == "production":
            if (
                not isinstance(fee_payer_signer, FilesystemFeePayerSigner)
                or getattr(fee_payer_signer, "is_test_signer", True)
            ):
                raise SettlementExecutionConfigError("production_fee_payer_signer_required")
            if getattr(rpc, "is_test_transport", True):
                raise SettlementExecutionConfigError("production_test_rpc_rejected")
        self._builder = builder
        self._solana_runtime = solana_runtime
        self._execution_config = execution_config
        self._fee_payer = fee_payer_signer
        self._rpc = rpc
        self._environment = environment
        self._mode = mode

    @property
    def rpc_transport(self):
        """Exact RPC object used for simulation; Phase 6D3 reuses this identity."""
        return self._rpc

    @property
    def execution_config(self) -> SettlementExecutionRuntimeConfig:
        return self._execution_config

    @property
    def solana_runtime(self) -> SolanaRuntimeConfig:
        return self._solana_runtime

    @classmethod
    def from_runtime_config(
        cls,
        *,
        builder: SettlementTransactionBuilder,
        runtime_config: ResolverRuntimeConfig,
        environ: Mapping[str, str] | None = None,
    ) -> "SettlementSimulationService":
        if not isinstance(runtime_config, ResolverRuntimeConfig):
            raise SettlementExecutionConfigError("validated_runtime_config_required")
        execution = runtime_config.settlement_execution
        if execution is None:
            raise SettlementExecutionConfigError("settlement_execution_config_missing")
        source = os.environ if environ is None else environ
        rpc_url = source.get(execution.rpc_url_env)
        if not isinstance(rpc_url, str) or not rpc_url.strip():
            raise SettlementExecutionConfigError("settlement_rpc_url_unresolved")
        try:
            fee_payer = FilesystemFeePayerSigner.from_environment(
                execution.fee_payer.keypair_path_env, environ=source
            )
            rpc = SolanaSettlementRpcClient(
                rpc_url,
                timeout_seconds=execution.rpc.timeout_seconds,
                commitment=execution.rpc.commitment,
                require_https=(
                    runtime_config.environment == "public-devnet"
                    and runtime_config.mode == "production"
                ),
            )
        except (SettlementFeePayerError, SettlementRpcError) as exc:
            raise SettlementExecutionConfigError("settlement_execution_dependency_invalid") from exc
        return cls(
            builder=builder,
            solana_runtime=runtime_config.solana,
            execution_config=execution,
            fee_payer_signer=fee_payer,
            rpc=rpc,
            environment=runtime_config.environment,
            mode=runtime_config.mode,
        )

    def simulate(self, request: SettlementSimulationRequest) -> SettlementSimulationResult:
        if not isinstance(request, SettlementSimulationRequest):
            raise SettlementExecutionBindingError("settlement_simulation_request_invalid")

        # Trust boundary comes first.  On mismatch there is no blockhash request,
        # construction, signing, or simulation against the endpoint.
        try:
            actual_genesis = self._rpc.get_genesis_hash()
        except SettlementRpcError as exc:
            raise SettlementExecutionRpcError("rpc_genesis_validation_failed") from exc
        if actual_genesis != self._execution_config.expected_genesis_hash:
            raise SettlementExecutionBindingError("rpc_genesis_hash_mismatch")

        try:
            recent_blockhash = self._rpc.get_latest_blockhash()
        except SettlementRpcError as exc:
            raise SettlementExecutionRpcError("rpc_blockhash_acquisition_failed") from exc

        # Phase 6D1 remains the only settlement transaction interpretation.
        unsigned = self._builder.build(
            SettlementTransactionInput(
                coordinator_job_id=request.coordinator_job_id,
                signing_intent_id=request.signing_intent_id,
                fee_payer_pubkey=str(self._fee_payer.public_key),
                recent_blockhash=recent_blockhash,
            )
        )
        if (
            unsigned.cluster != self._solana_runtime.cluster
            or unsigned.genesis_hash != self._solana_runtime.genesis_hash
            or unsigned.program_id != self._solana_runtime.prophet_program_id
        ):
            raise SettlementExecutionBindingError("constructed_transaction_runtime_identity_mismatch")
        self._validate_fee_payer_separation(unsigned)

        canonical_before = (
            unsigned.canonical_message,
            unsigned.canonical_message_digest,
            unsigned.signer_a_signature,
            unsigned.signer_b_signature,
        )
        try:
            signed_transaction = self._fee_payer.sign_transaction_message(unsigned.message)
        except SettlementFeePayerError as exc:
            raise SettlementExecutionSigningError("fee_payer_transaction_signing_failed") from exc
        self._validate_signed_transaction(unsigned, signed_transaction)
        canonical_after = (
            unsigned.canonical_message,
            unsigned.canonical_message_digest,
            unsigned.signer_a_signature,
            unsigned.signer_b_signature,
        )
        if canonical_after != canonical_before:
            raise SettlementExecutionBindingError("resolution_authorization_mutated_during_signing")

        serialized_transaction = bytes(signed_transaction)
        signed_artifact = SignedSettlementTransactionArtifact(
            coordinator_job_id=unsigned.coordinator_job_id,
            signing_intent_id=unsigned.signing_intent_id,
            program_id=unsigned.program_id,
            cluster=unsigned.cluster,
            genesis_hash=unsigned.genesis_hash,
            fee_payer_pubkey=unsigned.fee_payer_pubkey,
            recent_blockhash=unsigned.recent_blockhash,
            canonical_message_digest=unsigned.canonical_message_digest,
            canonical_message=unsigned.canonical_message,
            signer_a_public_key=unsigned.signer_a_public_key,
            signer_a_signature=unsigned.signer_a_signature,
            signer_b_public_key=unsigned.signer_b_public_key,
            signer_b_signature=unsigned.signer_b_signature,
            unsigned=unsigned,
            transaction=signed_transaction,
            serialized_transaction=serialized_transaction,
            transaction_signatures=tuple(str(sig) for sig in signed_transaction.signatures),
            transaction_digest=hashlib.sha256(serialized_transaction).hexdigest(),
        )

        try:
            simulation = self._rpc.simulate_transaction(signed_transaction)
        except SettlementRpcError as exc:
            raise SettlementExecutionRpcError("rpc_simulation_failed") from exc

        status = READY_CANDIDATE
        ready = True
        if simulation.program_error is not None:
            ready = False
            status = (
                STALE_BLOCKHASH
                if self._is_stale_blockhash_error(simulation.program_error)
                else PROGRAM_REJECTED
            )
        return SettlementSimulationResult(
            status=status,
            ready_for_submission=ready,
            transaction=signed_artifact,
            program_error=simulation.program_error,
            logs=simulation.logs,
            units_consumed=simulation.units_consumed,
            replacement_blockhash=simulation.replacement_blockhash,
            replacement_last_valid_block_height=simulation.replacement_last_valid_block_height,
        )

    def _validate_fee_payer_separation(self, artifact: SettlementTransactionArtifact) -> None:
        payer = artifact.fee_payer_pubkey
        if payer in {artifact.signer_a_public_key, artifact.signer_b_public_key}:
            raise SettlementExecutionBindingError("fee_payer_resolution_signer_identity_overlap")
        header = artifact.message.header
        account_keys = tuple(artifact.message.account_keys)
        if header.num_required_signatures != 1 or not account_keys:
            raise SettlementExecutionBindingError("unexpected_transaction_signer_set")
        if str(account_keys[0]) != payer:
            raise SettlementExecutionBindingError("fee_payer_signer_binding_mismatch")

    @staticmethod
    def _validate_signed_transaction(
        unsigned: SettlementTransactionArtifact,
        transaction: VersionedTransaction,
    ) -> None:
        if not isinstance(transaction, VersionedTransaction):
            raise SettlementExecutionSigningError("signed_transaction_invalid")
        if transaction.message != unsigned.message:
            raise SettlementExecutionSigningError("signed_transaction_message_mismatch")
        signatures = tuple(transaction.signatures)
        if len(signatures) != 1 or not isinstance(signatures[0], Signature):
            raise SettlementExecutionSigningError("signed_transaction_signature_set_invalid")
        try:
            if tuple(transaction.verify_with_results()) != (True,):
                raise ValueError
            transaction.verify_and_hash_message()
            if VersionedTransaction.from_bytes(bytes(transaction)) != transaction:
                raise ValueError
        except Exception as exc:
            raise SettlementExecutionSigningError("signed_transaction_local_verification_failed") from exc

    @staticmethod
    def _is_stale_blockhash_error(error: str) -> bool:
        normalized = error.replace("_", " ").replace("-", " ").lower()
        return "blockhashnotfound" in normalized.replace(" ", "") or "blockhash not found" in normalized
