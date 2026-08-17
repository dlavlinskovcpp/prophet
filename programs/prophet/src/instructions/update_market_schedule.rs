use super::UpdateMarketAuthority;
use crate::{errors::ErrorCode, events::MarketScheduleUpdated, state::MarketStatus};
use anchor_lang::prelude::*;

fn validate_schedule_update(
    now: i64,
    open_ts: i64,
    next_order_seq: u64,
    new_lock_ts: i64,
    new_resolve_ts: i64,
) -> Result<()> {
    // next_order_seq is monotonic and permanently records that at least one
    // order was accepted. Current open-order count is not a safe history bit.
    require!(next_order_seq == 0, ErrorCode::InvalidStage);
    require!(new_lock_ts > now, ErrorCode::InvalidTimeRange);
    require!(new_lock_ts >= open_ts, ErrorCode::InvalidTimeRange);
    require!(new_resolve_ts >= new_lock_ts, ErrorCode::InvalidTimeRange);
    Ok(())
}

pub(crate) fn update_market_schedule(
    ctx: Context<UpdateMarketAuthority>,
    new_lock_ts: i64,
    new_resolve_ts: i64,
) -> Result<()> {
    let market = &mut ctx.accounts.market;
    require!(
        market.status != MarketStatus::Resolved,
        ErrorCode::InvalidStage
    );

    let now = Clock::get()?.unix_timestamp;
    require!(now < market.lock_ts, ErrorCode::InvalidStage);
    validate_schedule_update(
        now,
        market.open_ts,
        market.next_order_seq,
        new_lock_ts,
        new_resolve_ts,
    )?;

    let old_lock_ts = market.lock_ts;
    let old_resolve_ts = market.resolve_ts;
    market.lock_ts = new_lock_ts;
    market.resolve_ts = new_resolve_ts;
    emit!(MarketScheduleUpdated {
        market: market.key(),
        authority: ctx.accounts.authority.key(),
        old_lock_ts,
        new_lock_ts,
        old_resolve_ts,
        new_resolve_ts,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_schedule_update;

    #[test]
    fn schedule_requires_future_lock_and_ordering_before_activity() {
        assert!(validate_schedule_update(100, 50, 0, 101, 101).is_ok());
        assert!(validate_schedule_update(100, 50, 0, 100, 101).is_err());
        assert!(validate_schedule_update(100, 50, 0, 99, 101).is_err());
        assert!(validate_schedule_update(100, 150, 0, 120, 150).is_err());
        assert!(validate_schedule_update(100, 50, 0, 101, 100).is_err());
    }

    #[test]
    fn schedule_is_permanently_frozen_after_first_accepted_order() {
        assert!(validate_schedule_update(100, 50, 1, 110, 120).is_err());
        assert!(validate_schedule_update(100, 50, 42, 110, 120).is_err());
    }
}
