"""Authoritative off-chain reconstruction of the frozen V2 resolution message."""
from __future__ import annotations
import struct
from solders.pubkey import Pubkey

DOMAIN_V2 = b"PROPHET_RESOLVE_V2"
RESOLUTION_MESSAGE_V2_LEN = 235

def build_resolution_message_v2(*, program_id: str, market: str, notary_config: str,
                                resolver_hash: bytes, open_ts: int, resolve_ts: int,
                                notary_config_version: int, outcome: str,
                                proof_hash: bytes, public_inputs_hash: bytes) -> bytes:
    if outcome not in {"YES", "NO", "INVALID"} or len(resolver_hash) != 32 or len(proof_hash) != 32 or len(public_inputs_hash) != 32:
        raise ValueError("invalid resolution message fields")
    message = (DOMAIN_V2 + bytes(Pubkey.from_string(program_id)) + bytes(Pubkey.from_string(market)) +
               bytes(Pubkey.from_string(notary_config)) + resolver_hash + struct.pack("<q", open_ts) +
               struct.pack("<q", resolve_ts) + struct.pack("<Q", notary_config_version) +
               bytes(({"YES": 1, "NO": 2, "INVALID": 3}[outcome],)) + proof_hash + public_inputs_hash)
    if len(message) != RESOLUTION_MESSAGE_V2_LEN:
        raise ValueError("resolution message length invalid")
    return message
