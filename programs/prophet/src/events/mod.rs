use crate::state::{MarketOutcome, MarketStatus, OrderSide};
use anchor_lang::prelude::*;

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
    pub fee_reserve_atoms: u64,
}

#[event]
pub struct OrdersMatched {
    pub market: Pubkey,
    pub order_yes: Pubkey,
    pub order_no: Pubkey,
    pub maker_order_seq: u64,
    pub taker_side: OrderSide,
    pub p_exec_e8: u32,
    pub qty_atoms: u64,
    pub cost_yes_atoms: u64,
    pub cost_no_atoms: u64,
    pub refund_yes_atoms: u64,
    pub refund_no_atoms: u64,
    pub fee_refund_yes_atoms: u64,
    pub fee_refund_no_atoms: u64,
    pub protocol_fee_yes_atoms: u64,
    pub protocol_fee_no_atoms: u64,
}

#[event]
pub struct OrderCancelled {
    pub market: Pubkey,
    pub order: Pubkey,
    pub owner: Pubkey,
    pub qty_remaining_atoms: u64,
    pub refund_atoms: u64,
    pub fee_refund_atoms: u64,
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
pub struct MarketStatusChanged {
    pub market: Pubkey,
    pub authority: Pubkey,
    pub old_status: MarketStatus,
    pub new_status: MarketStatus,
    pub effective_ts: i64,
}

#[event]
pub struct MarketScheduleUpdated {
    pub market: Pubkey,
    pub authority: Pubkey,
    pub old_lock_ts: i64,
    pub new_lock_ts: i64,
    pub old_resolve_ts: i64,
    pub new_resolve_ts: i64,
}

#[event]
pub struct MarketAuthorityTransferred {
    pub market: Pubkey,
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
}

#[event]
pub struct MarketFeeConfigUpdated {
    pub market: Pubkey,
    pub authority: Pubkey,
    pub old_fee_recipient: Pubkey,
    pub new_fee_recipient: Pubkey,
    pub old_protocol_fee_bps: u16,
    pub new_protocol_fee_bps: u16,
}

#[event]
pub struct ProtocolFeesWithdrawn {
    pub market: Pubkey,
    pub authority: Pubkey,
    pub fee_recipient: Pubkey,
    pub amount_atoms: u64,
    pub remaining_accrued_atoms: u64,
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

#[event]
pub struct NotaryConfigSnapshotCreated {
    pub previous_notary_config: Pubkey,
    pub new_notary_config: Pubkey,
    pub admin: Pubkey,
    pub previous_version: u64,
    pub new_version: u64,
    pub threshold: u8,
    pub notary_count: u8,
}
