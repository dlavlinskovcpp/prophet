use super::OrderSide;
use anchor_lang::prelude::*;

#[account]
pub struct Order {
    pub market: Pubkey,
    pub owner: Pubkey,
    pub side: OrderSide,
    pub seq: u64,
    pub limit_p_yes_e8: u32,
    pub qty_remaining_atoms: u64,
    pub escrow_remaining_atoms: u64,
    pub fee_remaining_atoms: u64,
    pub created_ts: i64,
    /// Sum of actual execution cost for fills where this order was the taker.
    pub taker_cost_basis_atoms: u64,
    /// Cumulative protocol fee already charged against `taker_cost_basis_atoms`.
    pub protocol_fee_paid_atoms: u64,
}

impl Order {
    // Serialized fields use 125 bytes. The pre-existing 128-byte allocation
    // already has room for the appended cumulative-fee counters.
    pub const LEN: usize = 128;
}
