from enum import IntEnum
from dataclasses import dataclass
from solders.pubkey import Pubkey


class OrderSide(IntEnum):
    BuyYes = 0
    BuyNo = 1


class MarketStatus(IntEnum):
    Open = 0
    Locked = 1
    Resolved = 2


class MarketOutcome(IntEnum):
    Undecided = 0
    Yes = 1
    No = 2
    Invalid = 3


class ClaimStatus(IntEnum):
    Open = 0
    Resolved = 1
    Redeemed = 2


class ClaimOutcome(IntEnum):
    Undecided = 0
    Pass = 1
    Fail = 2
    Invalid = 3


@dataclass
class MarketAccount:
    authority: Pubkey
    oracle_authority: Pubkey
    quote_mint: Pubkey
    quote_vault: Pubkey
    notary_config: Pubkey
    resolver_hash: bytes
    proof_hash: bytes
    public_inputs_hash: bytes
    open_ts: int
    lock_ts: int
    resolve_ts: int
    resolved_ts: int
    min_order_qty_atoms: int
    min_escrow_atoms: int
    next_order_seq: int
    open_orders_total: int
    max_open_orders_total: int
    max_open_orders_per_user: int
    quote_decimals: int
    status: MarketStatus
    outcome: MarketOutcome
    bump: int


@dataclass
class OrderAccount:
    market: Pubkey
    owner: Pubkey
    side: OrderSide
    seq: int
    limit_p_yes_e8: int
    qty_remaining_atoms: int
    escrow_remaining_atoms: int
    created_ts: int


@dataclass
class PositionAccount:
    market: Pubkey
    owner: Pubkey
    yes_shares_atoms: int
    no_shares_atoms: int
    pending_refunds_atoms: int
    open_orders: int
    redeemed: bool


@dataclass
class ClaimAccount:
    issuer: Pubkey
    pass_recipient: Pubkey
    fail_recipient: Pubkey
    oracle_authority: Pubkey
    quote_mint: Pubkey
    quote_vault: Pubkey
    notary_config: Pubkey
    resolver_hash: bytes
    proof_hash: bytes
    public_inputs_hash: bytes
    claim_id: int
    bond_atoms: int
    created_ts: int
    resolve_ts: int
    resolved_ts: int
    status: ClaimStatus
    outcome: ClaimOutcome
    bump: int
    reserved0: bytes
