use super::UpdateMarketAuthority;
use crate::{errors::ErrorCode, events::MarketStatusChanged, state::MarketStatus};
use anchor_lang::prelude::*;

pub(crate) fn unlock_market(ctx: Context<UpdateMarketAuthority>) -> Result<()> {
    let market = &mut ctx.accounts.market;
    require!(
        market.status != MarketStatus::Resolved,
        ErrorCode::InvalidStage
    );

    let now = Clock::get()?.unix_timestamp;
    require!(now < market.lock_ts, ErrorCode::CannotUnlockAfterLockTs);
    let old_status = market.status;
    if old_status != MarketStatus::Open {
        market.status = MarketStatus::Open;
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
