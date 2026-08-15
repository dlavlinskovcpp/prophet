use super::UpdateMarketAuthority;
use crate::{
    errors::ErrorCode,
    events::MarketResolved,
    state::{MarketOutcome, MarketStatus},
};
use anchor_lang::prelude::*;

pub(crate) fn emergency_resolve_invalid(
    ctx: Context<UpdateMarketAuthority>,
    proof_hash: [u8; 32],
    public_inputs_hash: [u8; 32],
) -> Result<()> {
    let market = &mut ctx.accounts.market;
    require!(
        market.status == MarketStatus::Locked,
        ErrorCode::MarketNotLocked
    );

    let now = Clock::get()?.unix_timestamp;
    market.status = MarketStatus::Resolved;
    market.outcome = MarketOutcome::Invalid;
    market.proof_hash = proof_hash;
    market.public_inputs_hash = public_inputs_hash;
    market.resolved_ts = now;
    emit!(MarketResolved {
        market: market.key(),
        outcome: MarketOutcome::Invalid,
        resolved_ts: now,
        proof_hash,
        public_inputs_hash,
    });
    Ok(())
}
