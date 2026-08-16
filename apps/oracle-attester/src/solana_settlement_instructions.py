"""Network-free adapter over the existing Prophet settlement instruction builder.

Phase 6D1 must not introduce a second interpretation of the on-chain settlement
interface.  The authoritative client implementation remains
``SolanaClient.build_resolve_threshold_ix``.  This module invokes that exact
method on an uninitialised instance so no RPC client, keypair, or filesystem
secret is constructed as part of transaction building.
"""
from __future__ import annotations

from solders.instruction import Instruction
from solders.pubkey import Pubkey


def build_resolve_threshold_instruction(
    *,
    program_id: Pubkey,
    market: Pubkey,
    notary_config: Pubkey,
    outcome_idx: int,
    proof_hash: bytes,
    public_inputs_hash: bytes,
) -> Instruction:
    """Call the repository's existing ``build_resolve_threshold_ix`` path exactly."""
    # Lazy import keeps this pure construction adapter free from module-import
    # coupling until it is actually used.  ``__init__`` is deliberately bypassed:
    # it constructs an RPC client and loads keypairs, neither of which belongs to
    # Phase 6D1 transaction construction.
    from .solana_client import SolanaClient

    client = object.__new__(SolanaClient)
    client.program_id = program_id
    return SolanaClient.build_resolve_threshold_ix(
        client,
        market=market,
        notary_config=notary_config,
        outcome_idx=outcome_idx,
        proof_hash=proof_hash,
        public_inputs_hash=public_inputs_hash,
    )
