"""Prepare and reconcile one immutable transaction identity per submission."""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import List, Optional

from solana.rpc.api import Client
from solana.rpc.commitment import Commitment, Confirmed
from solana.rpc.types import TxOpts
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.signature import Signature
from solders.transaction import VersionedTransaction

logger = logging.getLogger(__name__)


class TransactionPreparationError(RuntimeError):
    """The transaction could not be prepared before any RPC submission."""


class TransactionIdentityMismatch(RuntimeError):
    """The RPC returned a signature different from the locally signed bytes."""


class TransactionExecutionError(RuntimeError):
    """The validator reported an on-chain transaction error."""


class UnknownCommitState(RuntimeError):
    """The exact transaction may have been accepted but its final state is unknown."""

    def __init__(
        self,
        *,
        signature: str,
        transaction_digest: str,
        recent_blockhash: str,
        last_valid_block_height: Optional[int],
        reason: str,
    ) -> None:
        self.signature = signature
        self.transaction_digest = transaction_digest
        self.recent_blockhash = recent_blockhash
        self.last_valid_block_height = last_valid_block_height
        self.reason = reason
        super().__init__(
            "transaction commit state unknown "
            f"for signature {signature} (digest {transaction_digest}): {reason}"
        )


@dataclass(frozen=True)
class PreparedTransaction:
    """The exact identity retained across all submission/reconciliation attempts."""

    raw_bytes: bytes
    signature: str
    recent_blockhash: str
    last_valid_block_height: Optional[int]
    transaction_digest: str


def _commitment_rank(value: object) -> int:
    normalized = str(value).lower()
    if normalized.endswith("processed"):
        return 0
    if normalized.endswith("confirmed"):
        return 1
    if normalized.endswith("finalized"):
        return 2
    return -1


def _commitment_satisfied(observed: object, requested: Commitment) -> bool:
    return _commitment_rank(observed) >= _commitment_rank(requested)


def _status_from_response(response: object) -> object:
    values = getattr(response, "value", None)
    if isinstance(values, (list, tuple)) and values:
        return values[0]
    return None


def _rpc_signature(signature: str) -> object:
    try:
        return Signature.from_string(signature)
    except (TypeError, ValueError):
        # Small fakes and alternative Client implementations may accept the
        # textual form directly; the real solana-py client receives Signature.
        return signature


def _build_transaction(
    client: Client,
    final_instructions: List[Instruction],
    payer: Keypair,
    all_signers: List[Keypair],
    commitment: Commitment,
) -> PreparedTransaction:
    try:
        blockhash_resp = client.get_latest_blockhash(commitment=commitment)
        blockhash_value = blockhash_resp.value
        blockhash = blockhash_value.blockhash
        last_valid_block_height = getattr(blockhash_value, "last_valid_block_height", None)
        message = MessageV0.try_compile(
            payer=payer.pubkey(),
            instructions=final_instructions,
            address_lookup_table_accounts=[],
            recent_blockhash=blockhash,
        )
        transaction = VersionedTransaction(message, all_signers)
        raw_bytes = bytes(transaction)
        signatures = getattr(transaction, "signatures", None)
        if not signatures:
            raise TransactionPreparationError("signed transaction has no local signature")
        signature = str(signatures[0])
    except TransactionPreparationError:
        raise
    except Exception as exc:
        raise TransactionPreparationError("unable to prepare transaction before submission") from exc

    return PreparedTransaction(
        raw_bytes=raw_bytes,
        signature=signature,
        recent_blockhash=str(blockhash),
        last_valid_block_height=last_valid_block_height,
        transaction_digest=hashlib.sha256(raw_bytes).hexdigest(),
    )


def _raise_if_terminal(status: object, prepared: PreparedTransaction) -> None:
    error = getattr(status, "err", None)
    if error is not None:
        raise TransactionExecutionError(
            f"transaction {prepared.signature} failed on-chain: {error}"
        )


def _expired(client: Client, prepared: PreparedTransaction, commitment: Commitment) -> bool:
    if prepared.last_valid_block_height is None:
        return False
    get_block_height = getattr(client, "get_block_height", None)
    if get_block_height is None:
        return False
    try:
        current = get_block_height(commitment=commitment).value
    except Exception:
        return False
    return int(current) > int(prepared.last_valid_block_height)


def _unknown(prepared: PreparedTransaction, reason: str) -> UnknownCommitState:
    return UnknownCommitState(
        signature=prepared.signature,
        transaction_digest=prepared.transaction_digest,
        recent_blockhash=prepared.recent_blockhash,
        last_valid_block_height=prepared.last_valid_block_height,
        reason=reason,
    )


def _get_signature_statuses(client: Client, signature: object, textual_signature: str) -> object:
    """Read one exact signature across solana-py provider versions."""
    try:
        return client.get_signature_statuses([signature], search_transaction_history=True)
    except TypeError:
        # Some compatible clients expose the older textual parameter shape.
        # This is a read-only compatibility retry; no transaction is resent.
        return client.get_signature_statuses([textual_signature], search_transaction_history=True)


def submit_and_confirm(
    client: Client,
    instructions: List[Instruction],
    payer: Keypair,
    signers: Optional[List[Keypair]] = None,
    timeout_s: float = 30,
    compute_unit_limit: Optional[int] = None,
    compute_unit_price_micro_lamports: Optional[int] = None,
    skip_preflight: bool = False,
    commitment: Commitment = Confirmed,
) -> str:
    """Submit one signed transaction and reconcile that same identity.

    Once ``send_raw_transaction`` is attempted, every later submission uses the
    exact same bytes. This synchronous call owns the complete reconciliation
    window and never creates a second financial transaction after an ambiguous
    RPC outcome.
    """
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")

    final_instructions: List[Instruction] = []
    if compute_unit_limit is not None:
        final_instructions.append(set_compute_unit_limit(compute_unit_limit))
    if compute_unit_price_micro_lamports is not None:
        final_instructions.append(set_compute_unit_price(compute_unit_price_micro_lamports))
    final_instructions.extend(instructions)

    all_signers: List[Keypair] = []
    seen_signers = set()
    for signer in [payer] + (signers or []):
        signer_key = bytes(signer.pubkey())
        if signer_key in seen_signers:
            continue
        seen_signers.add(signer_key)
        all_signers.append(signer)

    prepared = _build_transaction(client, final_instructions, payer, all_signers, commitment)
    logger.info(
        "prepared transaction signature=%s digest=%s blockhash=%s last_valid_block_height=%s",
        prepared.signature,
        prepared.transaction_digest,
        prepared.recent_blockhash,
        prepared.last_valid_block_height,
    )

    deadline = time.monotonic() + timeout_s
    next_rebroadcast = 0.0
    send_attempted = False
    last_rpc_error: Optional[Exception] = None
    rpc_signature = _rpc_signature(prepared.signature)

    while time.monotonic() < deadline:
        now = time.monotonic()
        if not send_attempted or now >= next_rebroadcast:
            try:
                send_resp = client.send_raw_transaction(
                    prepared.raw_bytes,
                    opts=TxOpts(
                        skip_preflight=skip_preflight,
                        preflight_commitment=commitment,
                    ),
                )
                returned_signature = getattr(send_resp, "value", None)
                if returned_signature is not None:
                    returned_text = str(returned_signature)
                    if returned_text != prepared.signature:
                        raise TransactionIdentityMismatch(
                            "RPC returned a signature different from the locally signed transaction"
                        )
                    # Keep the same typed lookup value used by the real RPC
                    # client; only the textual comparison is remote evidence.
                    rpc_signature = _rpc_signature(returned_text)
                logger.info("submitted exact transaction bytes signature=%s", prepared.signature)
            except TransactionIdentityMismatch:
                raise
            except Exception as exc:
                last_rpc_error = exc
                logger.warning(
                    "transaction submission/rebroadcast outcome is ambiguous signature=%s digest=%s error=%s",
                    prepared.signature,
                    prepared.transaction_digest,
                    type(exc).__name__,
                )
            finally:
                send_attempted = True
                next_rebroadcast = time.monotonic() + 1.0

        try:
            status_response = _get_signature_statuses(client, rpc_signature, prepared.signature)
            status = _status_from_response(status_response)
            if status is not None:
                _raise_if_terminal(status, prepared)
                observed = getattr(status, "confirmation_status", None)
                if observed is not None and _commitment_satisfied(observed, commitment):
                    return prepared.signature
        except TransactionExecutionError:
            raise
        except Exception as exc:
            last_rpc_error = exc
            logger.warning(
                "transaction status query failed signature=%s digest=%s error=%s",
                prepared.signature,
                prepared.transaction_digest,
                type(exc).__name__,
            )

        if _expired(client, prepared, commitment):
            reason = "recent blockhash expired before the requested commitment was proven"
            if last_rpc_error is not None:
                reason += f"; last RPC error {type(last_rpc_error).__name__}"
            raise _unknown(prepared, reason)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.5, remaining))

    reason = "reconciliation timeout without a terminal status"
    if last_rpc_error is not None:
        reason += f"; last RPC error {type(last_rpc_error).__name__}"
    raise _unknown(prepared, reason)
