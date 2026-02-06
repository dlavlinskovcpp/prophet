use anchor_lang::prelude::*;
use crate::state::{OrderSide, MarketOutcome};

#[event]
pub struct OrderPlaced {
    pub market: Pubkey,
    pub order: Pubkey,
    pub owner: Pubkey,
    pub side: OrderSide,
    pub seq: u64,
    pub limit_p_yes_e8: u32,
    pub qty_atoms: u64,
    pub escrow_atoms: u64,
}

#[event]
pub struct OrdersMatched {
    pub market: Pubkey,
    pub order_yes: Pubkey,
    pub order_no: Pubkey,
    pub maker_order_seq: u64,
    pub p_exec_e8: u32,
    pub qty_atoms: u64,
    pub cost_yes_atoms: u64,
    pub cost_no_atoms: u64,
    pub refund_yes_atoms: u64,
    pub refund_no_atoms: u64,
}

#[event]
pub struct OrderCancelled {
    pub market: Pubkey,
    pub order: Pubkey,
    pub owner: Pubkey,
    pub qty_remaining_atoms: u64,
    pub refund_atoms: u64,
}

#[event]
pub struct RefundClaimed {
    pub market: Pubkey,
    pub owner: Pubkey,
    pub amount_atoms: u64,
}

#[event]
pub struct MarketResolved {
    pub market: Pubkey,
    pub outcome: MarketOutcome,
    pub resolved_ts: i64,
    pub proof_hash: [u8; 32],
    pub public_inputs_hash: [u8; 32],
}

#[event]
pub struct Redeemed {
    pub market: Pubkey,
    pub owner: Pubkey,
    pub outcome: MarketOutcome,
    pub payout_atoms: u64,
    pub yes_burned_atoms: u64,
    pub no_burned_atoms: u64,
}