use crate::{
    errors::ErrorCode,
    events::NotaryConfigSnapshotCreated,
    state::NotaryConfig,
    validation::{
        replace_notary_keys, validate_notary_config_snapshot_address, validate_notary_set,
        validate_stored_notary_config,
    },
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(new_version: u64)]
pub struct RotateNotaryConfig<'info> {
    #[account(has_one = admin)]
    pub previous_notary_config: Box<Account<'info, NotaryConfig>>,
    #[account(
        init,
        payer = admin,
        space = 8 + NotaryConfig::LEN,
        seeds = [
            b"notary_config",
            admin.key().as_ref(),
            &new_version.to_le_bytes()
        ],
        bump
    )]
    pub new_notary_config: Box<Account<'info, NotaryConfig>>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub(crate) fn rotate_notary_config(
    ctx: Context<RotateNotaryConfig>,
    new_version: u64,
    threshold: u8,
    notary_keys: Vec<Pubkey>,
) -> Result<()> {
    let previous = &ctx.accounts.previous_notary_config;
    validate_notary_config_snapshot_address(&previous.key(), previous, &crate::ID)?;
    validate_stored_notary_config(previous)?;
    validate_notary_set(threshold, &notary_keys)?;

    let expected_version = previous
        .version
        .checked_add(1)
        .ok_or(ErrorCode::MathOverflow)?;
    require!(
        new_version == expected_version && new_version > 1,
        ErrorCode::InvalidNotaryConfigVersion
    );

    let config = &mut ctx.accounts.new_notary_config;
    config.admin = ctx.accounts.admin.key();
    config.threshold = threshold;
    config.notary_count = notary_keys.len() as u8;
    config.bump = ctx.bumps.new_notary_config;
    config.version = new_version;
    replace_notary_keys(&mut config.notary_keys, 0, &notary_keys);

    emit!(NotaryConfigSnapshotCreated {
        previous_notary_config: previous.key(),
        new_notary_config: config.key(),
        admin: ctx.accounts.admin.key(),
        previous_version: previous.version,
        new_version,
        threshold,
        notary_count: config.notary_count,
    });
    Ok(())
}
