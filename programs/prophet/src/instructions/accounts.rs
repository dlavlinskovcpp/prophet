use crate::{errors::ErrorCode, state::Market};
use anchor_lang::prelude::*;

/// Shared account contract for authority-governed market instructions.
#[derive(Accounts)]
pub struct UpdateMarketAuthority<'info> {
    #[account(
        mut,
        has_one = authority @ ErrorCode::UnauthorizedMarketAuthority,
        seeds = [
            b"market",
            market.creator.as_ref(),
            market.resolver_hash.as_ref(),
            &market.open_ts.to_le_bytes(),
            &market.market_nonce.to_le_bytes(),
        ],
        bump = market.bump
    )]
    pub market: Account<'info, Market>,
    pub authority: Signer<'info>,
}
