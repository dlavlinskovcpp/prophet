use crate::{
    errors::ErrorCode,
    events::RefundClaimed,
    state::{Market, Position},
    utils::market_signer_open_ts_bytes,
};
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[derive(Accounts)]
pub struct ClaimRefunds<'info> {
    #[account(seeds = [b"market", market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes()], bump = market.bump)]
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

pub(crate) fn claim_refunds(ctx: Context<ClaimRefunds>, amount_atoms: u64) -> Result<()> {
    let position = &mut ctx.accounts.position;
    let market = &ctx.accounts.market;
    let claim_amount = amount_atoms.min(position.pending_refunds_atoms);
    require!(claim_amount > 0, ErrorCode::NoRefunds);

    position.pending_refunds_atoms = position
        .pending_refunds_atoms
        .checked_sub(claim_amount)
        .ok_or(ErrorCode::MathOverflow)?;
    let open_ts_bytes = market_signer_open_ts_bytes(market);
    let signer_seeds = &[
        b"market".as_ref(),
        market.resolver_hash.as_ref(),
        open_ts_bytes.as_ref(),
        std::slice::from_ref(&market.bump),
    ];
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.quote_vault.to_account_info(),
                to: ctx.accounts.owner_quote_ata.to_account_info(),
                authority: market.to_account_info(),
            },
            &[signer_seeds],
        ),
        claim_amount,
    )?;
    emit!(RefundClaimed {
        market: market.key(),
        owner: position.owner,
        amount_atoms: claim_amount,
    });
    Ok(())
}
