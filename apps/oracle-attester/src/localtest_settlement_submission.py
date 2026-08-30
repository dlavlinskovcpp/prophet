"""Localtest-only MessageV0 construction and one-shot finalized submission."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from solana.rpc.types import TxOpts
from solana.rpc.commitment import Finalized
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from prophet_sdk.ed25519 import build_ed25519_ix
from prophet_sdk.settlement_message import build_resolution_message_v2

from .localtest_chain_binding import LocaltestChainBindingV1
from .localtest_raw_settlement_bridge import LocaltestRawSettlementSignaturesV1
from .localtest_solana_finalized_rpc import LocaltestSolanaFinalizedRpc
from .solana_settlement_instructions import build_resolve_threshold_instruction


class LocaltestSettlementError(RuntimeError):
    pass


@dataclass(frozen=True)
class LocaltestSettlementArtifact:
    message: MessageV0
    instructions: tuple[Instruction, Instruction, Instruction]
    canonical_message: bytes
    transaction: VersionedTransaction | None = None
    signature: str | None = None


def build_localtest_settlement_message(*, binding: LocaltestChainBindingV1, signatures: LocaltestRawSettlementSignaturesV1, fee_payer_pubkey: str, recent_blockhash: str) -> LocaltestSettlementArtifact:
    if not isinstance(binding, LocaltestChainBindingV1) or not isinstance(signatures, LocaltestRawSettlementSignaturesV1):
        raise LocaltestSettlementError("localtest_settlement_inputs_invalid")
    try:
        payer = Pubkey.from_string(fee_payer_pubkey)
        blockhash = Hash.from_string(recent_blockhash)
        expected_message = build_resolution_message_v2(
            program_id=binding["program_id"], market=binding["market"], notary_config=binding["notary_config"],
            resolver_hash=bytes.fromhex(binding["resolver_definition_hash"]), open_ts=binding["open_ts"],
            resolve_ts=binding["resolve_ts"], notary_config_version=binding["notary_config_version"],
            outcome=binding["outcome"], proof_hash=bytes.fromhex(binding["proof_hash"]),
            public_inputs_hash=bytes.fromhex(binding["public_inputs_hash"]),
        )
        signatures.validate(
            expected_message=expected_message,
            signer_a_id=signatures.signer_a_id,
            signer_a_public_key=binding["signer_a_public_key"],
            signer_a_key_version=signatures.signer_a_key_version,
            signer_b_id=signatures.signer_b_id,
            signer_b_public_key=binding["signer_b_public_key"],
            signer_b_key_version=signatures.signer_b_key_version,
        )
        if signatures.canonical_message[:18] != b"PROPHET_RESOLVE_V2":
            raise ValueError
        a_ix = build_ed25519_ix(signatures.canonical_message, signatures.signer_a_signature, bytes(Pubkey.from_string(binding["signer_a_public_key"])))
        b_ix = build_ed25519_ix(signatures.canonical_message, signatures.signer_b_signature, bytes(Pubkey.from_string(binding["signer_b_public_key"])))
        resolve_ix = build_resolve_threshold_instruction(
            program_id=Pubkey.from_string(binding["program_id"]),
            market=Pubkey.from_string(binding["market"]),
            notary_config=Pubkey.from_string(binding["notary_config"]),
            outcome_idx={"YES": 1, "NO": 2, "INVALID": 3}[binding["outcome"]],
            proof_hash=bytes.fromhex(binding["proof_hash"]),
            public_inputs_hash=bytes.fromhex(binding["public_inputs_hash"]),
        )
        instructions = (a_ix, b_ix, resolve_ix)
        message = MessageV0.try_compile(payer=payer, instructions=list(instructions), address_lookup_table_accounts=[], recent_blockhash=blockhash)
        if message.header.num_required_signatures != 1 or message.account_keys[0] != payer:
            raise ValueError
        return LocaltestSettlementArtifact(message=message, instructions=instructions, canonical_message=signatures.canonical_message)
    except LocaltestSettlementError:
        raise
    except Exception as exc:
        raise LocaltestSettlementError("localtest_settlement_message_invalid") from exc


def sign_localtest_fee_payer(artifact: LocaltestSettlementArtifact, fee_payer: Keypair) -> LocaltestSettlementArtifact:
    if not isinstance(fee_payer, Keypair) or artifact.message.account_keys[0] != fee_payer.pubkey() or artifact.message.header.num_required_signatures != 1:
        raise LocaltestSettlementError("localtest_fee_payer_binding_invalid")
    try:
        tx = VersionedTransaction(artifact.message, [fee_payer])
        if tuple(tx.verify_with_results()) != (True,):
            raise ValueError
        return LocaltestSettlementArtifact(artifact.message, artifact.instructions, artifact.canonical_message, tx)
    except LocaltestSettlementError:
        raise
    except Exception as exc:
        raise LocaltestSettlementError("localtest_fee_payer_signing_failed") from exc


def submit_localtest_settlement(*, rpc: LocaltestSolanaFinalizedRpc, artifact: LocaltestSettlementArtifact, timeout_seconds: float = 45.0) -> LocaltestSettlementArtifact:
    if not isinstance(rpc, LocaltestSolanaFinalizedRpc) or artifact.transaction is None:
        raise LocaltestSettlementError("localtest_settlement_transaction_required")
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise LocaltestSettlementError("localtest_settlement_timeout_invalid")
    client = rpc.client
    try:
        simulation = client.simulate_transaction(artifact.transaction, sig_verify=True, commitment=Finalized)
        if simulation.value.err is not None:
            raise LocaltestSettlementError("localtest_settlement_simulation_failed")
        response = client.send_raw_transaction(bytes(artifact.transaction), opts=TxOpts(skip_preflight=True))
        signature = response.value
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            status_response = client.get_signature_statuses([signature], search_transaction_history=True)
            status = status_response.value[0] if status_response.value else None
            if status is not None:
                if status.err is not None:
                    raise LocaltestSettlementError("localtest_settlement_chain_error")
                confirmation = str(status.confirmation_status).lower()
                if confirmation == "finalized" or confirmation.endswith(".finalized"):
                    return LocaltestSettlementArtifact(artifact.message, artifact.instructions, artifact.canonical_message, artifact.transaction, str(signature))
            time.sleep(0.15)
        raise LocaltestSettlementError("localtest_settlement_finalization_timeout")
    except LocaltestSettlementError:
        raise
    except Exception as exc:
        raise LocaltestSettlementError("localtest_settlement_submission_failed") from exc
