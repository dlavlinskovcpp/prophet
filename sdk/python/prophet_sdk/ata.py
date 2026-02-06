import logging
import time
from typing import Optional
from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.instruction import Instruction, AccountMeta
from .tx import submit_and_confirm

logger = logging.getLogger(__name__)

TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
ASSOCIATED_TOKEN_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
SYSTEM_PROGRAM_ID = Pubkey.from_string("11111111111111111111111111111111")
SYSVAR_RENT_ID = Pubkey.from_string("SysvarRent111111111111111111111111111111111")

def derive_ata(owner: Pubkey, mint: Pubkey) -> Pubkey:
    seeds = [bytes(owner), bytes(TOKEN_PROGRAM_ID), bytes(mint)]
    pda, _ = Pubkey.find_program_address(seeds, ASSOCIATED_TOKEN_PROGRAM_ID)
    return pda

def build_create_ata_ix(
    payer: Pubkey,
    owner: Pubkey,
    mint: Pubkey,
    ata: Pubkey,
    idempotent: bool = True
) -> Instruction:
    data = bytes([1]) if idempotent else bytes([0])
    
    keys = [
        AccountMeta(payer, True, True),
        AccountMeta(ata, False, True),
        AccountMeta(owner, False, False),
        AccountMeta(mint, False, False),
        AccountMeta(SYSTEM_PROGRAM_ID, False, False),
        AccountMeta(TOKEN_PROGRAM_ID, False, False),
        AccountMeta(SYSVAR_RENT_ID, False, False),
    ]
    
    # solders Instruction(program_id, data, accounts)
    return Instruction(
        ASSOCIATED_TOKEN_PROGRAM_ID,
        data,
        keys
    )

def ensure_ata(
    client: Client,
    payer: Keypair,
    owner: Pubkey,
    mint: Pubkey
) -> Pubkey:
    ata = derive_ata(owner, mint)
    
    resp = client.get_account_info(ata)
    if resp.value is not None:
        return ata
        
    logger.info(f"Creating ATA {ata} for owner {owner}...")
    
    try:
        ix = build_create_ata_ix(payer.pubkey(), owner, mint, ata, idempotent=True)
        submit_and_confirm(client, [ix], payer)
        if client.get_account_info(ata).value is not None:
            return ata
    except Exception as e:
        logger.warning(f"CreateIdempotent failed: {e}. Retrying with legacy Create...")
    
    try:
        ix_legacy = build_create_ata_ix(payer.pubkey(), owner, mint, ata, idempotent=False)
        submit_and_confirm(client, [ix_legacy], payer)
    except Exception as e:
        if client.get_account_info(ata).value is not None:
            return ata
        raise e
    
    if client.get_account_info(ata).value is None:
        raise RuntimeError(f"Failed to create ATA {ata} after retries")
        
    return ata