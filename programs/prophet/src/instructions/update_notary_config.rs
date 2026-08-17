use crate::{errors::ErrorCode, state::NotaryConfig};
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
    _ctx: Context<UpdateNotaryConfig>,
    _threshold: u8,
    _notary_keys: Vec<Pubkey>,
) -> Result<()> {
    err!(ErrorCode::NotaryConfigImmutable)
}
