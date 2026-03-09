import base64
from typing import Union

from construct import Bytes
from borsh_construct import CStruct, I64, U8, U16, U32, U64
from solders.pubkey import Pubkey

from .types import (
    MarketAccount,
    MarketOutcome,
    MarketStatus,
    OrderAccount,
    OrderSide,
    PositionAccount,
)

# Borsh layouts matching programs/prophet/src/state.rs
MarketLayout = CStruct(
    "authority" / Bytes(32),
    "oracle_authority" / Bytes(32),
    "quote_mint" / Bytes(32),
    "quote_vault" / Bytes(32),
    "fee_recipient" / Bytes(32),
    "notary_config" / Bytes(32),
    "resolver_hash" / Bytes(32),
    "proof_hash" / Bytes(32),
    "public_inputs_hash" / Bytes(32),
    "open_ts" / I64,
    "lock_ts" / I64,
    "resolve_ts" / I64,
    "resolved_ts" / I64,
    "min_order_qty_atoms" / U64,
    "min_escrow_atoms" / U64,
    "accrued_protocol_fees_atoms" / U64,
    "next_order_seq" / U64,
    "open_orders_total" / U32,
    "max_open_orders_total" / U32,
    "max_open_orders_per_user" / U16,
    "protocol_fee_bps" / U16,
    "_reserved0" / Bytes(6),
    "quote_decimals" / U8,
    "status" / U8,
    "outcome" / U8,
    "bump" / U8,
)

OrderLayout = CStruct(
    "market" / Bytes(32),
    "owner" / Bytes(32),
    "side" / U8,
    "seq" / U64,
    "limit_p_yes_e8" / U32,
    "qty_remaining_atoms" / U64,
    "escrow_remaining_atoms" / U64,
    "fee_remaining_atoms" / U64,
    "created_ts" / I64,
)

PositionLayout = CStruct(
    "market" / Bytes(32),
    "owner" / Bytes(32),
    "yes_shares_atoms" / U64,
    "no_shares_atoms" / U64,
    "pending_refunds_atoms" / U64,
    "open_orders" / U16,
    "redeemed" / U8,
)


def extract_account_bytes(data_obj: Union[bytes, str, list, tuple]) -> bytes:
    if isinstance(data_obj, bytes):
        return data_obj
    if isinstance(data_obj, (list, tuple)):
        if len(data_obj) >= 1 and isinstance(data_obj[0], str):
            return base64.b64decode(data_obj[0])
    if isinstance(data_obj, str):
        return base64.b64decode(data_obj)
    if hasattr(data_obj, "decoded"):
        return data_obj.decoded
    raise ValueError(f"Unknown account data format: {type(data_obj)}")


def decode_market(data: bytes) -> MarketAccount:
    if len(data) < 8:
        raise ValueError("Account data too short")
    parsed = MarketLayout.parse(data[8:])
    return MarketAccount(
        authority=Pubkey.from_bytes(parsed.authority),
        oracle_authority=Pubkey.from_bytes(parsed.oracle_authority),
        quote_mint=Pubkey.from_bytes(parsed.quote_mint),
        quote_vault=Pubkey.from_bytes(parsed.quote_vault),
        fee_recipient=Pubkey.from_bytes(parsed.fee_recipient),
        notary_config=Pubkey.from_bytes(parsed.notary_config),
        resolver_hash=bytes(parsed.resolver_hash),
        proof_hash=bytes(parsed.proof_hash),
        public_inputs_hash=bytes(parsed.public_inputs_hash),
        open_ts=parsed.open_ts,
        lock_ts=parsed.lock_ts,
        resolve_ts=parsed.resolve_ts,
        resolved_ts=parsed.resolved_ts,
        min_order_qty_atoms=parsed.min_order_qty_atoms,
        min_escrow_atoms=parsed.min_escrow_atoms,
        accrued_protocol_fees_atoms=parsed.accrued_protocol_fees_atoms,
        next_order_seq=parsed.next_order_seq,
        open_orders_total=parsed.open_orders_total,
        max_open_orders_total=parsed.max_open_orders_total,
        max_open_orders_per_user=parsed.max_open_orders_per_user,
        protocol_fee_bps=parsed.protocol_fee_bps,
        quote_decimals=parsed.quote_decimals,
        status=MarketStatus(parsed.status),
        outcome=MarketOutcome(parsed.outcome),
        bump=parsed.bump,
    )


def decode_order(data: bytes) -> OrderAccount:
    if len(data) < 8:
        raise ValueError("Account data too short")
    parsed = OrderLayout.parse(data[8:])
    return OrderAccount(
        market=Pubkey.from_bytes(parsed.market),
        owner=Pubkey.from_bytes(parsed.owner),
        side=OrderSide(parsed.side),
        seq=parsed.seq,
        limit_p_yes_e8=parsed.limit_p_yes_e8,
        qty_remaining_atoms=parsed.qty_remaining_atoms,
        escrow_remaining_atoms=parsed.escrow_remaining_atoms,
        fee_remaining_atoms=parsed.fee_remaining_atoms,
        created_ts=parsed.created_ts,
    )


def decode_position(data: bytes) -> PositionAccount:
    if len(data) < 8:
        raise ValueError("Account data too short")
    parsed = PositionLayout.parse(data[8:])
    return PositionAccount(
        market=Pubkey.from_bytes(parsed.market),
        owner=Pubkey.from_bytes(parsed.owner),
        yes_shares_atoms=parsed.yes_shares_atoms,
        no_shares_atoms=parsed.no_shares_atoms,
        pending_refunds_atoms=parsed.pending_refunds_atoms,
        open_orders=parsed.open_orders,
        redeemed=bool(parsed.redeemed),
    )
