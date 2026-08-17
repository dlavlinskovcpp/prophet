import os
import struct
from typing import Optional, Tuple

from solders.pubkey import Pubkey

DEFAULT_PROGRAM_ID = Pubkey.from_string(
    os.getenv("PROPHET_PROGRAM_ID", "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A")
)


def get_program_id(program_id: Optional[Pubkey] = None) -> Pubkey:
    return program_id or DEFAULT_PROGRAM_ID


def derive_market_pda(
    resolver_hash: bytes,
    open_ts: int,
    program_id: Optional[Pubkey] = None,
) -> Tuple[Pubkey, int]:
    pid = get_program_id(program_id)
    seeds = [b"market", resolver_hash, struct.pack("<q", open_ts)]
    return Pubkey.find_program_address(seeds, pid)


def derive_order_pda(
    market: Pubkey,
    owner: Pubkey,
    seq: int,
    program_id: Optional[Pubkey] = None,
) -> Tuple[Pubkey, int]:
    pid = get_program_id(program_id)
    seeds = [b"order", bytes(market), bytes(owner), struct.pack("<Q", seq)]
    return Pubkey.find_program_address(seeds, pid)


def derive_position_pda(
    market: Pubkey,
    owner: Pubkey,
    program_id: Optional[Pubkey] = None,
) -> Tuple[Pubkey, int]:
    pid = get_program_id(program_id)
    seeds = [b"position", bytes(market), bytes(owner)]
    return Pubkey.find_program_address(seeds, pid)


def derive_notary_config_snapshot_pda(
    admin: Pubkey,
    version: int,
    program_id: Optional[Pubkey] = None,
) -> Tuple[Pubkey, int]:
    if isinstance(version, bool) or not isinstance(version, int) or not 0 < version < (1 << 64):
        raise ValueError("Notary config snapshot version must be a positive u64")
    pid = get_program_id(program_id)
    seeds = [b"notary_config", bytes(admin)]
    if version > 1:
        seeds.append(struct.pack("<Q", version))
    return Pubkey.find_program_address(seeds, pid)


def derive_notary_config_pda(
    admin: Pubkey,
    program_id: Optional[Pubkey] = None,
) -> Tuple[Pubkey, int]:
    return derive_notary_config_snapshot_pda(admin, 1, program_id)


def derive_associated_token_account(owner: Pubkey, mint: Pubkey) -> Pubkey:
    spl_associated_token_account_program_id = Pubkey.from_string(
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
    )
    spl_token_program_id = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

    seeds = [bytes(owner), bytes(spl_token_program_id), bytes(mint)]
    pda, _ = Pubkey.find_program_address(seeds, spl_associated_token_account_program_id)
    return pda
