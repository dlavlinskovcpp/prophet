use super::UpdateMarketAuthority;
use crate::{errors::ErrorCode, events::MarketScheduleUpdated, state::MarketStatus};
use anchor_lang::prelude::*;

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
    require!(
        market.open_orders_total == 0,
        ErrorCode::MarketHasOpenOrders
    );
    require!(new_lock_ts >= market.open_ts, ErrorCode::InvalidTimeRange);
    require!(new_resolve_ts >= new_lock_ts, ErrorCode::InvalidTimeRange);

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
