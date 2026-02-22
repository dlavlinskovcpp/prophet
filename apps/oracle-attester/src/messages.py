import struct

from solders.pubkey import Pubkey

DOMAIN_V1 = b"PROPHET_RESOLVE_V1"
DOMAIN_V2 = b"PROPHET_RESOLVE_V2"
CLAIM_DOMAIN_V1 = b"PROPHET_CLAIM_RESOLVE_V1"
CLAIM_DOMAIN_V2 = b"PROPHET_CLAIM_RESOLVE_V2"


def build_market_message_v1(
    market_pubkey: Pubkey,
    resolver_hash: bytes,
    open_ts: int,
    outcome_idx: int,
    proof_hash: bytes,
    public_inputs_hash: bytes,
) -> bytes:
    return (
        DOMAIN_V1
        + bytes(market_pubkey)
        + resolver_hash
        + struct.pack("<q", open_ts)
        + struct.pack("B", outcome_idx)
        + proof_hash
        + public_inputs_hash
    )


def build_market_message_v2(
    program_id: Pubkey,
    market_pubkey: Pubkey,
    notary_config_pubkey: Pubkey,
    resolver_hash: bytes,
    open_ts: int,
    resolve_ts: int,
    outcome_idx: int,
    proof_hash: bytes,
    public_inputs_hash: bytes,
) -> bytes:
    return (
        DOMAIN_V2
        + bytes(program_id)
        + bytes(market_pubkey)
        + bytes(notary_config_pubkey)
        + resolver_hash
        + struct.pack("<q", open_ts)
        + struct.pack("<q", resolve_ts)
        + struct.pack("B", outcome_idx)
        + proof_hash
        + public_inputs_hash
    )


def build_claim_message_v1(
    program_id: Pubkey,
    claim_pubkey: Pubkey,
    resolver_hash: bytes,
    issuer: Pubkey,
    claim_id: int,
    resolve_ts: int,
    outcome_idx: int,
    proof_hash: bytes,
    public_inputs_hash: bytes,
) -> bytes:
    return (
        CLAIM_DOMAIN_V1
        + bytes(program_id)
        + bytes(claim_pubkey)
        + resolver_hash
        + bytes(issuer)
        + struct.pack("<Q", claim_id)
        + struct.pack("<q", resolve_ts)
        + struct.pack("B", outcome_idx)
        + proof_hash
        + public_inputs_hash
    )


def build_claim_message_v2(
    program_id: Pubkey,
    claim_pubkey: Pubkey,
    notary_config_pubkey: Pubkey,
    resolver_hash: bytes,
    issuer: Pubkey,
    claim_id: int,
    resolve_ts: int,
    outcome_idx: int,
    proof_hash: bytes,
    public_inputs_hash: bytes,
) -> bytes:
    return (
        CLAIM_DOMAIN_V2
        + bytes(program_id)
        + bytes(claim_pubkey)
        + bytes(notary_config_pubkey)
        + resolver_hash
        + bytes(issuer)
        + struct.pack("<Q", claim_id)
        + struct.pack("<q", resolve_ts)
        + struct.pack("B", outcome_idx)
        + proof_hash
        + public_inputs_hash
    )
