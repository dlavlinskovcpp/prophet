use super::UpdateMarketAuthority;
use crate::{errors::ErrorCode, events::MarketStatusChanged, state::MarketStatus};
use anchor_lang::prelude::*;

fn require_scheduled_lock_reached(now: i64, lock_ts: i64) -> Result<()> {
    require!(now >= lock_ts, ErrorCode::InvalidStage);
    Ok(())
}

pub(crate) fn lock_market(ctx: Context<UpdateMarketAuthority>) -> Result<()> {
    let market = &mut ctx.accounts.market;
    require!(
        market.status != MarketStatus::Resolved,
        ErrorCode::InvalidStage
    );

    let now = Clock::get()?.unix_timestamp;
    require_scheduled_lock_reached(now, market.lock_ts)?;

    let old_status = market.status;
    if old_status != MarketStatus::Locked {
        market.status = MarketStatus::Locked;
        emit!(MarketStatusChanged {
            market: market.key(),
            authority: ctx.accounts.authority.key(),
            old_status,
            new_status: market.status,
            effective_ts: now,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_scheduled_lock_reached;

    #[test]
    fn manual_lock_respects_exact_schedule_boundary() {
        assert!(require_scheduled_lock_reached(99, 100).is_err());
        assert!(require_scheduled_lock_reached(100, 100).is_ok());
        assert!(require_scheduled_lock_reached(101, 100).is_ok());
    }
}
