use super::UpdateMarketAuthority;
use crate::{
    errors::ErrorCode,
    events::MarketResolved,
    state::{MarketOutcome, MarketStatus},
};
use anchor_lang::prelude::*;

fn require_emergency_resolution_time(now: i64, resolve_ts: i64) -> Result<()> {
    require!(now >= resolve_ts, ErrorCode::MarketNotResolvableYet);
    Ok(())
}

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
    require_emergency_resolution_time(now, market.resolve_ts)?;

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

#[cfg(test)]
mod tests {
    use super::require_emergency_resolution_time;

    #[test]
    fn emergency_invalid_respects_resolution_boundary() {
        assert!(require_emergency_resolution_time(199, 200).is_err());
        assert!(require_emergency_resolution_time(200, 200).is_ok());
        assert!(require_emergency_resolution_time(201, 200).is_ok());
    }
}
