#![allow(unexpected_cfgs)]
#![allow(clippy::diverging_sub_expression)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod events;
mod instructions;
mod math;
pub mod state;
mod utils;
mod validation;

#[cfg(feature = "fuzzing")]
pub mod fuzzing;
#[cfg(test)]
mod security_tests;

pub use instructions::*;
use state::{MarketOutcome, OrderSide};

declare_id!("3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE");

// Stable Anchor entrypoints. Business logic lives in one file per instruction
// under `instructions/`; these wrappers intentionally preserve the deployed API.
#[program]
pub mod prophet {
    use super::*;

    pub fn initialize_notary_config(
        ctx: Context<InitializeNotaryConfig>,
        threshold: u8,
        notary_keys: Vec<Pubkey>,
    ) -> Result<()> {
        instructions::initialize_notary_config(ctx, threshold, notary_keys)
    }

    pub fn update_notary_config(
        ctx: Context<UpdateNotaryConfig>,
        threshold: u8,
        notary_keys: Vec<Pubkey>,
    ) -> Result<()> {
        instructions::update_notary_config(ctx, threshold, notary_keys)
    }

    pub fn rotate_notary_config(
        ctx: Context<RotateNotaryConfig>,
        new_version: u64,
        threshold: u8,
        notary_keys: Vec<Pubkey>,
    ) -> Result<()> {
        instructions::rotate_notary_config(ctx, new_version, threshold, notary_keys)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn initialize_market_v2(
        ctx: Context<InitializeMarketV2>,
        resolver_hash: [u8; 32],
        open_ts: i64,
        lock_ts: i64,
        resolve_ts: i64,
        min_order_qty_atoms: u64,
        min_escrow_atoms: u64,
        max_open_orders_per_user: u16,
        max_open_orders_total: u32,
    ) -> Result<()> {
        instructions::initialize_market_v2(
            ctx,
            resolver_hash,
            open_ts,
            lock_ts,
            resolve_ts,
            min_order_qty_atoms,
            min_escrow_atoms,
            max_open_orders_per_user,
            max_open_orders_total,
        )
    }

    pub fn transfer_market_authority(
        ctx: Context<UpdateMarketAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::transfer_market_authority::transfer_market_authority(ctx, new_authority)
    }

    pub fn lock_market(ctx: Context<UpdateMarketAuthority>) -> Result<()> {
        instructions::lock_market::lock_market(ctx)
    }

    pub fn unlock_market(ctx: Context<UpdateMarketAuthority>) -> Result<()> {
        instructions::unlock_market::unlock_market(ctx)
    }

    pub fn sync_market_status(ctx: Context<SyncMarketStatus>) -> Result<()> {
        instructions::sync_market_status(ctx)
    }

    pub fn update_market_schedule(
        ctx: Context<UpdateMarketAuthority>,
        new_lock_ts: i64,
        new_resolve_ts: i64,
    ) -> Result<()> {
        instructions::update_market_schedule::update_market_schedule(
            ctx,
            new_lock_ts,
            new_resolve_ts,
        )
    }

    pub fn set_market_fee_config(
        ctx: Context<UpdateMarketAuthority>,
        fee_recipient: Pubkey,
        protocol_fee_bps: u16,
    ) -> Result<()> {
        instructions::set_market_fee_config::set_market_fee_config(
            ctx,
            fee_recipient,
            protocol_fee_bps,
        )
    }

    pub fn place_order(
        ctx: Context<PlaceOrder>,
        order_seq: u64,
        side: OrderSide,
        limit_p_yes_e8: u32,
        qty_atoms: u64,
    ) -> Result<()> {
        instructions::place_order(ctx, order_seq, side, limit_p_yes_e8, qty_atoms)
    }

    pub fn match_orders(ctx: Context<MatchOrders>, max_qty_atoms: u64) -> Result<()> {
        instructions::match_orders(ctx, max_qty_atoms)
    }

    pub fn cancel_order(ctx: Context<CancelOrder>) -> Result<()> {
        instructions::cancel_order(ctx)
    }

    pub fn claim_refunds(ctx: Context<ClaimRefunds>, amount_atoms: u64) -> Result<()> {
        instructions::claim_refunds(ctx, amount_atoms)
    }

    pub fn withdraw_protocol_fees(
        ctx: Context<WithdrawProtocolFees>,
        amount_atoms: u64,
    ) -> Result<()> {
        instructions::withdraw_protocol_fees(ctx, amount_atoms)
    }

    pub fn resolve_market_threshold(
        ctx: Context<ResolveMarketThreshold>,
        outcome: MarketOutcome,
        proof_hash: [u8; 32],
        public_inputs_hash: [u8; 32],
    ) -> Result<()> {
        instructions::resolve_market_threshold(ctx, outcome, proof_hash, public_inputs_hash)
    }

    pub fn redeem(ctx: Context<Redeem>) -> Result<()> {
        instructions::redeem(ctx)
    }

    pub fn emergency_resolve_invalid(
        ctx: Context<UpdateMarketAuthority>,
        proof_hash: [u8; 32],
        public_inputs_hash: [u8; 32],
    ) -> Result<()> {
        instructions::emergency_resolve_invalid::emergency_resolve_invalid(
            ctx,
            proof_hash,
            public_inputs_hash,
        )
    }
}
