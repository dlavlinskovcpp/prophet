use crate::{
    errors::ErrorCode,
    events::Redeemed,
    math::redemption_payout,
    state::{Market, MarketStatus, Position},
};
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[derive(Accounts)]
pub struct Redeem<'info> {
    #[account(mut, seeds = [b"market", market.creator.as_ref(), market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes(), &market.market_nonce.to_le_bytes()], bump = market.bump)]
    pub market: Account<'info, Market>,
    #[account(
        mut,
        seeds = [b"position", market.key().as_ref(), owner.key().as_ref()],
        bump,
        constraint = position.market == market.key() @ ErrorCode::InvalidMarket,
        constraint = position.owner == owner.key() @ ErrorCode::InvalidMarket
    )]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        constraint = quote_vault.key() == market.quote_vault,
        constraint = quote_vault.mint == market.quote_mint,
        constraint = quote_vault.owner == market.key()
    )]
    pub quote_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = owner_quote_ata.mint == market.quote_mint,
        constraint = owner_quote_ata.owner == owner.key()
    )]
    pub owner_quote_ata: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

pub(crate) fn redeem(ctx: Context<Redeem>) -> Result<()> {
    let market = &mut ctx.accounts.market;
    let position = &mut ctx.accounts.position;
    require!(
        market.status == MarketStatus::Resolved,
        ErrorCode::MarketNotResolved
    );

    let yes = position.yes_shares_atoms;
    let no = position.no_shares_atoms;
    let (payout, invalid_payout_remainder) =
        redemption_payout(market.outcome, yes, no, market.invalid_payout_remainder)?;
    position.yes_shares_atoms = 0;
    position.no_shares_atoms = 0;
    position.redeemed = true;
    market.invalid_payout_remainder = invalid_payout_remainder;

    if payout > 0 {
        let open_ts_bytes = market.open_ts.to_le_bytes();
        let market_nonce_bytes = market.market_nonce.to_le_bytes();
        let seeds = &[
            b"market".as_ref(),
            market.creator.as_ref(),
            market.resolver_hash.as_ref(),
            open_ts_bytes.as_ref(),
            market_nonce_bytes.as_ref(),
            &[market.bump],
        ];
        token::transfer(
            CpiContext::new_with_signer(
                Token::id(),
                Transfer {
                    from: ctx.accounts.quote_vault.to_account_info(),
                    to: ctx.accounts.owner_quote_ata.to_account_info(),
                    authority: market.to_account_info(),
                },
                &[&seeds[..]],
            ),
            payout,
        )?;
    }

    emit!(Redeemed {
        market: market.key(),
        owner: position.owner,
        outcome: market.outcome,
        payout_atoms: payout,
        yes_burned_atoms: yes,
        no_burned_atoms: no,
    });
    Ok(())
}
