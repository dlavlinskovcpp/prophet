use crate::{
    errors::ErrorCode,
    events::MarketResolved,
    state::{Market, MarketOutcome, MarketStatus, NotaryConfig},
    utils::resolution_message_v2,
    validation::{
        count_valid_notary_signatures, validate_notary_config_snapshot_address,
        validate_stored_notary_config,
    },
};
use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::SysvarId;

#[derive(Accounts)]
pub struct ResolveMarketThreshold<'info> {
    #[account(
        mut,
        seeds = [b"market", market.creator.as_ref(), market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes(), &market.market_nonce.to_le_bytes()],
        bump = market.bump
    )]
    pub market: Box<Account<'info, Market>>,
    pub notary_config: Box<Account<'info, NotaryConfig>>,
    /// CHECK: Checked via address constraint.
    #[account(address = Instructions::id())]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

pub(crate) fn resolve_market_threshold(
    ctx: Context<ResolveMarketThreshold>,
    outcome: MarketOutcome,
    proof_hash: [u8; 32],
    public_inputs_hash: [u8; 32],
) -> Result<()> {
    let market = &mut ctx.accounts.market;
    let config = &ctx.accounts.notary_config;
    let now = Clock::get()?.unix_timestamp;

    require!(now >= market.resolve_ts, ErrorCode::MarketNotResolvableYet);
    require!(
        market.status != MarketStatus::Resolved,
        ErrorCode::InvalidStage
    );
    require!(
        outcome != MarketOutcome::Undecided,
        ErrorCode::InvalidOutcome
    );
    require!(
        market.notary_config != Pubkey::default(),
        ErrorCode::NotaryConfigNotSet
    );
    require!(
        market.notary_config == config.key(),
        ErrorCode::NotaryConfigMismatch
    );
    validate_notary_config_snapshot_address(&config.key(), config, &crate::ID)?;
    // New Market V2 creation admits only the operated 2-of-2 topology, while
    // existing snapshots remain generically resolvable for compatibility.
    validate_stored_notary_config(config)?;

    let expected_message = resolution_message_v2(
        &crate::ID,
        &market.key(),
        market,
        &config.key(),
        config,
        outcome,
        &proof_hash,
        &public_inputs_hash,
    );
    let valid_count = count_valid_notary_signatures(
        &ctx.accounts.instructions_sysvar.to_account_info(),
        config,
        &expected_message,
    )?;
    require!(
        valid_count >= config.threshold,
        ErrorCode::NotEnoughNotarySigs
    );

    market.status = MarketStatus::Resolved;
    market.outcome = outcome;
    market.proof_hash = proof_hash;
    market.public_inputs_hash = public_inputs_hash;
    market.resolved_ts = now;
    emit!(MarketResolved {
        market: market.key(),
        outcome,
        resolved_ts: now,
        proof_hash,
        public_inputs_hash,
    });
    Ok(())
}
