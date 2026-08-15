use crate::{
    errors::ErrorCode,
    state::{Market, MarketOutcome, MarketStatus, NotaryConfig},
    validation::{validate_market_configuration, validate_stored_notary_config},
};
use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Token, TokenAccount},
};

#[derive(Accounts)]
#[instruction(resolver_hash: [u8; 32], open_ts: i64)]
pub struct InitializeMarketV2<'info> {
    #[account(
        init,
        seeds = [b"market", resolver_hash.as_ref(), &open_ts.to_le_bytes()],
        bump,
        payer = authority,
        space = 8 + Market::LEN
    )]
    pub market: Box<Account<'info, Market>>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: Legacy field; unused for threshold resolution.
    pub oracle_authority: AccountInfo<'info>,
    pub quote_mint: Box<Account<'info, token::Mint>>,
    #[account(
        init,
        payer = authority,
        associated_token::mint = quote_mint,
        associated_token::authority = market
    )]
    pub quote_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        seeds = [b"notary_config", notary_config.admin.as_ref()],
        bump = notary_config.bump
    )]
    pub notary_config: Box<Account<'info, NotaryConfig>>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn initialize_market_v2(
    ctx: Context<InitializeMarketV2>,
    resolver_hash: [u8; 32],
    open_ts: i64,
    lock_ts: i64,
    resolve_ts: i64,
    min_order_qty_atoms: u64,
    min_escrow_atoms: u64,
    max_open_orders_per_user: u16,
    max_open_orders_total: u32,
) -> Result<()> {
    require!(lock_ts >= open_ts, ErrorCode::InvalidTimeRange);
    require!(resolve_ts >= lock_ts, ErrorCode::InvalidTimeRange);
    validate_market_configuration(
        min_order_qty_atoms,
        min_escrow_atoms,
        max_open_orders_per_user,
        max_open_orders_total,
    )?;
    validate_stored_notary_config(&ctx.accounts.notary_config)?;

    let authority_key = ctx.accounts.authority.key();
    let market = &mut ctx.accounts.market;
    market.authority = authority_key;
    market.oracle_authority = ctx.accounts.oracle_authority.key();
    market.quote_mint = ctx.accounts.quote_mint.key();
    market.quote_vault = ctx.accounts.quote_vault.key();
    market.fee_recipient = authority_key;
    market.quote_decimals = ctx.accounts.quote_mint.decimals;
    market.notary_config = ctx.accounts.notary_config.key();
    market.resolver_hash = resolver_hash;
    market.open_ts = open_ts;
    market.lock_ts = lock_ts;
    market.resolve_ts = resolve_ts;
    market.min_order_qty_atoms = min_order_qty_atoms;
    market.min_escrow_atoms = min_escrow_atoms;
    market.max_open_orders_per_user = max_open_orders_per_user;
    market.max_open_orders_total = max_open_orders_total;
    market.protocol_fee_bps = 0;
    market.status = MarketStatus::Open;
    market.outcome = MarketOutcome::Undecided;
    market.bump = ctx.bumps.market;
    Ok(())
}
