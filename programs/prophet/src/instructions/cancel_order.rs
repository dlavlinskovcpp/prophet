use crate::{
    errors::ErrorCode,
    events::OrderCancelled,
    state::{Market, Order, Position},
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CancelOrder<'info> {
    #[account(
        mut,
        seeds = [b"market", market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes()],
        bump = market.bump
    )]
    pub market: Account<'info, Market>,
    #[account(
        mut,
        has_one = owner,
        has_one = market,
        seeds = [b"order", market.key().as_ref(), owner.key().as_ref(), &order.seq.to_le_bytes()],
        bump
    )]
    pub order: Account<'info, Order>,
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
}

pub(crate) fn cancel_order(ctx: Context<CancelOrder>) -> Result<()> {
    let order = &mut ctx.accounts.order;
    let position = &mut ctx.accounts.position;
    let market = &mut ctx.accounts.market;

    let fee_refund = order.fee_remaining_atoms;
    let refund = order
        .escrow_remaining_atoms
        .checked_add(fee_refund)
        .ok_or(ErrorCode::MathOverflow)?;
    let qty_remaining = order.qty_remaining_atoms;
    position.pending_refunds_atoms = position
        .pending_refunds_atoms
        .checked_add(refund)
        .ok_or(ErrorCode::MathOverflow)?;
    market.open_orders_total = market
        .open_orders_total
        .checked_sub(1)
        .ok_or(ErrorCode::MathOverflow)?;
    position.open_orders = position
        .open_orders
        .checked_sub(1)
        .ok_or(ErrorCode::MathOverflow)?;

    emit!(OrderCancelled {
        market: market.key(),
        order: order.key(),
        owner: ctx.accounts.owner.key(),
        qty_remaining_atoms: qty_remaining,
        refund_atoms: refund,
        fee_refund_atoms: fee_refund,
    });
    order.close(ctx.accounts.owner.to_account_info())?;
    Ok(())
}
