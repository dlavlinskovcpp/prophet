use super::UpdateMarketAuthority;
use crate::{errors::ErrorCode, events::MarketAuthorityTransferred};
use anchor_lang::prelude::*;

pub(crate) fn transfer_market_authority(
    ctx: Context<UpdateMarketAuthority>,
    new_authority: Pubkey,
) -> Result<()> {
    let market = &mut ctx.accounts.market;
    require!(
        new_authority != Pubkey::default(),
        ErrorCode::InvalidNewAuthority
    );
    require!(
        new_authority != market.authority,
        ErrorCode::InvalidNewAuthority
    );
    require!(
        new_authority != market.key() && new_authority != crate::ID,
        ErrorCode::InvalidNewAuthority
    );

    let old_authority = market.authority;
    market.authority = new_authority;
    emit!(MarketAuthorityTransferred {
        market: market.key(),
        old_authority,
        new_authority,
    });
    Ok(())
}
