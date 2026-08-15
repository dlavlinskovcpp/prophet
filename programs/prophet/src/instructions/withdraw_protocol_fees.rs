use crate::{
    errors::ErrorCode, events::ProtocolFeesWithdrawn, state::Market,
    utils::market_signer_open_ts_bytes, validation::validate_fee_withdrawal_accounts,
};
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[derive(Accounts)]
pub struct WithdrawProtocolFees<'info> {
    #[account(
        mut,
        has_one = authority @ ErrorCode::UnauthorizedMarketAuthority,
        seeds = [b"market", market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes()],
        bump = market.bump
    )]
    pub market: Account<'info, Market>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub quote_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub fee_recipient_quote_ata: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

pub(crate) fn withdraw_protocol_fees(
    ctx: Context<WithdrawProtocolFees>,
    amount_atoms: u64,
) -> Result<()> {
    let market = &mut ctx.accounts.market;
    validate_fee_withdrawal_accounts(
        market,
        &ctx.accounts.quote_vault,
        &ctx.accounts.fee_recipient_quote_ata,
    )?;

    let withdraw_amount = amount_atoms.min(market.accrued_protocol_fees_atoms);
    require!(withdraw_amount > 0, ErrorCode::NoProtocolFees);
    market.accrued_protocol_fees_atoms = market
        .accrued_protocol_fees_atoms
        .checked_sub(withdraw_amount)
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
                to: ctx.accounts.fee_recipient_quote_ata.to_account_info(),
                authority: market.to_account_info(),
            },
            &[signer_seeds],
        ),
        withdraw_amount,
    )?;
    emit!(ProtocolFeesWithdrawn {
        market: market.key(),
        authority: ctx.accounts.authority.key(),
        fee_recipient: market.fee_recipient,
        amount_atoms: withdraw_amount,
        remaining_accrued_atoms: market.accrued_protocol_fees_atoms,
    });
    Ok(())
}
