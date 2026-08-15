use crate::{
    events::MarketStatusChanged,
    state::{Market, MarketStatus},
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SyncMarketStatus<'info> {
    #[account(
        mut,
        seeds = [b"market", market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes()],
        bump = market.bump
    )]
    pub market: Account<'info, Market>,
}

pub(crate) fn sync_market_status(ctx: Context<SyncMarketStatus>) -> Result<()> {
    let market = &mut ctx.accounts.market;
    if market.status != MarketStatus::Open {
        return Ok(());
    }

    let now = Clock::get()?.unix_timestamp;
    if now < market.lock_ts {
        return Ok(());
    }

    let old_status = market.status;
    market.status = MarketStatus::Locked;
    emit!(MarketStatusChanged {
        market: market.key(),
        authority: market.authority,
        old_status,
        new_status: market.status,
        effective_ts: now,
    });
    Ok(())
}
