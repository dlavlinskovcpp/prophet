use super::UpdateMarketAuthority;
use crate::{
    errors::ErrorCode,
    events::MarketFeeConfigUpdated,
    state::{MarketStatus, MAX_PROTOCOL_FEE_BPS},
};
use anchor_lang::prelude::*;

pub(crate) fn set_market_fee_config(
    ctx: Context<UpdateMarketAuthority>,
    fee_recipient: Pubkey,
    protocol_fee_bps: u16,
) -> Result<()> {
    let market = &mut ctx.accounts.market;
    require!(
        market.status != MarketStatus::Resolved,
        ErrorCode::InvalidStage
    );
    require!(market.next_order_seq == 0, ErrorCode::FeeConfigFrozen);
    require!(
        fee_recipient != Pubkey::default(),
        ErrorCode::InvalidFeeRecipient
    );
    require!(
        fee_recipient != market.key() && fee_recipient != crate::ID,
        ErrorCode::InvalidFeeRecipient
    );
    require!(
        protocol_fee_bps <= MAX_PROTOCOL_FEE_BPS,
        ErrorCode::InvalidProtocolFeeBps
    );

    let old_fee_recipient = market.fee_recipient;
    let old_protocol_fee_bps = market.protocol_fee_bps;
    market.fee_recipient = fee_recipient;
    market.protocol_fee_bps = protocol_fee_bps;
    emit!(MarketFeeConfigUpdated {
        market: market.key(),
        authority: ctx.accounts.authority.key(),
        old_fee_recipient,
        new_fee_recipient: fee_recipient,
        old_protocol_fee_bps,
        new_protocol_fee_bps: protocol_fee_bps,
    });
    Ok(())
}
