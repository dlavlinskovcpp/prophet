use crate::{
    state::{NotaryConfig, MAX_NOTARIES},
    validation::{replace_notary_keys, validate_notary_set},
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct InitializeNotaryConfig<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + NotaryConfig::LEN,
        seeds = [b"notary_config", admin.key().as_ref()],
        bump
    )]
    pub notary_config: Box<Account<'info, NotaryConfig>>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub(crate) fn initialize_notary_config(
    ctx: Context<InitializeNotaryConfig>,
    threshold: u8,
    notary_keys: Vec<Pubkey>,
) -> Result<()> {
    validate_notary_set(threshold, &notary_keys)?;

    let config = &mut ctx.accounts.notary_config;
    config.admin = ctx.accounts.admin.key();
    config.threshold = threshold;
    config.notary_count = notary_keys.len() as u8;
    config.version = 1;
    config.bump = ctx.bumps.notary_config;
    replace_notary_keys(&mut config.notary_keys, 0, &notary_keys);
    debug_assert!(config.notary_count as usize <= MAX_NOTARIES);
    Ok(())
}
