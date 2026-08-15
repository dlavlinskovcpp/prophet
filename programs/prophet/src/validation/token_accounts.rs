use crate::{errors::ErrorCode, state::Market};
use anchor_lang::prelude::*;
use anchor_spl::token::TokenAccount;

pub(crate) fn validate_fee_withdrawal_accounts(
    market: &Account<Market>,
    quote_vault: &Account<TokenAccount>,
    fee_recipient_quote_ata: &Account<TokenAccount>,
) -> Result<()> {
    let quote_vault_key = quote_vault.key();
    require!(
        quote_vault_key != fee_recipient_quote_ata.key(),
        ErrorCode::InvalidFeeRecipient
    );
    require!(
        quote_vault_key == market.quote_vault,
        ErrorCode::InvalidFeeRecipient
    );
    require!(
        quote_vault.mint == market.quote_mint,
        ErrorCode::InvalidFeeRecipient
    );
    require!(
        quote_vault.owner == market.key(),
        ErrorCode::InvalidFeeRecipient
    );
    require!(
        fee_recipient_quote_ata.owner == market.fee_recipient,
        ErrorCode::InvalidFeeRecipient
    );
    require!(
        fee_recipient_quote_ata.mint == market.quote_mint,
        ErrorCode::InvalidFeeRecipient
    );
    Ok(())
}
