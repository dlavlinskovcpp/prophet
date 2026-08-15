use crate::{
    errors::ErrorCode,
    state::NotaryConfig,
    validation::{replace_notary_keys, validate_notary_set},
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UpdateNotaryConfig<'info> {
    #[account(
        mut,
        seeds = [b"notary_config", admin.key().as_ref()],
        bump = notary_config.bump,
        has_one = admin
    )]
    pub notary_config: Box<Account<'info, NotaryConfig>>,
    #[account(mut)]
    pub admin: Signer<'info>,
}

pub(crate) fn update_notary_config(
    ctx: Context<UpdateNotaryConfig>,
    threshold: u8,
    notary_keys: Vec<Pubkey>,
) -> Result<()> {
    let config = &mut ctx.accounts.notary_config;
    validate_notary_set(threshold, &notary_keys)?;

    let previous_count = config.notary_count as usize;
    config.threshold = threshold;
    config.notary_count = notary_keys.len() as u8;
    config.version = config
        .version
        .checked_add(1)
        .ok_or(ErrorCode::MathOverflow)?;
    replace_notary_keys(&mut config.notary_keys, previous_count, &notary_keys);
    Ok(())
}
