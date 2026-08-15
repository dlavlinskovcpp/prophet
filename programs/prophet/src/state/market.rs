use super::{MarketOutcome, MarketStatus};
use anchor_lang::prelude::*;

#[account]
pub struct Market {
    pub authority: Pubkey,
    // Deprecated signer field retained for account-layout compatibility.
    pub oracle_authority: Pubkey,
    pub quote_mint: Pubkey,
    pub quote_vault: Pubkey,
    pub fee_recipient: Pubkey,
    pub notary_config: Pubkey,
    pub resolver_hash: [u8; 32],
    pub proof_hash: [u8; 32],
    pub public_inputs_hash: [u8; 32],
    pub open_ts: i64,
    pub lock_ts: i64,
    pub resolve_ts: i64,
    pub resolved_ts: i64,
    pub min_order_qty_atoms: u64,
    pub min_escrow_atoms: u64,
    pub accrued_protocol_fees_atoms: u64,
    pub next_order_seq: u64,
    pub open_orders_total: u32,
    pub max_open_orders_total: u32,
    pub max_open_orders_per_user: u16,
    pub protocol_fee_bps: u16,
    pub _reserved0: [u8; 6],
    pub quote_decimals: u8,
    pub status: MarketStatus,
    pub outcome: MarketOutcome,
    pub bump: u8,
    /// Carries the half-atom remainder between Invalid-outcome redemptions.
    /// Appended into the account's pre-existing zero padding for compatibility.
    pub invalid_payout_remainder: u8,
}

impl Market {
    /// Existing allocation retained verbatim for account compatibility.
    pub const LEN: usize = 384;
}
