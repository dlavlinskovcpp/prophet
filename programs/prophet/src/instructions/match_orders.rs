use crate::{
    errors::ErrorCode,
    events::OrdersMatched,
    math::{settle_crossing_orders, MatchOrderState},
    state::{Market, Order, OrderSide, Position},
    validation::require_market_open_for_trading,
};
use anchor_lang::prelude::*;
use anchor_spl::token::TokenAccount;

#[derive(Accounts)]
pub struct MatchOrders<'info> {
    #[account(
        mut,
        seeds = [b"market", market.creator.as_ref(), market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes(), &market.market_nonce.to_le_bytes()],
        bump = market.bump
    )]
    pub market: Box<Account<'info, Market>>,
    #[account(
        mut,
        has_one = market @ ErrorCode::InvalidMarket,
        seeds = [b"order", market.key().as_ref(), order_yes.owner.as_ref(), &order_yes.seq.to_le_bytes()],
        bump
    )]
    pub order_yes: Box<Account<'info, Order>>,
    #[account(
        mut,
        has_one = market @ ErrorCode::InvalidMarket,
        seeds = [b"order", market.key().as_ref(), order_no.owner.as_ref(), &order_no.seq.to_le_bytes()],
        bump
    )]
    pub order_no: Box<Account<'info, Order>>,
    #[account(
        mut,
        seeds = [b"position", market.key().as_ref(), order_yes.owner.as_ref()],
        bump,
        constraint = position_yes.market == market.key() @ ErrorCode::InvalidMarket,
        constraint = position_yes.owner == order_yes.owner @ ErrorCode::InvalidMarket
    )]
    pub position_yes: Box<Account<'info, Position>>,
    #[account(
        mut,
        seeds = [b"position", market.key().as_ref(), order_no.owner.as_ref()],
        bump,
        constraint = position_no.market == market.key() @ ErrorCode::InvalidMarket,
        constraint = position_no.owner == order_no.owner @ ErrorCode::InvalidMarket
    )]
    pub position_no: Box<Account<'info, Position>>,
    /// CHECK: Address checked via constraint.
    #[account(mut, address = order_yes.owner)]
    pub owner_yes: UncheckedAccount<'info>,
    /// CHECK: Address checked via constraint.
    #[account(mut, address = order_no.owner)]
    pub owner_no: UncheckedAccount<'info>,
    #[account(
        constraint = market_quote_vault.key() == market.quote_vault,
        constraint = market_quote_vault.mint == market.quote_mint,
        constraint = market_quote_vault.owner == market.key()
    )]
    pub market_quote_vault: Box<Account<'info, TokenAccount>>,
}

pub(crate) fn match_orders(ctx: Context<MatchOrders>, max_qty_atoms: u64) -> Result<()> {
    let market = &mut ctx.accounts.market;
    let order_yes = &mut ctx.accounts.order_yes;
    let order_no = &mut ctx.accounts.order_no;
    let position_yes = &mut ctx.accounts.position_yes;
    let position_no = &mut ctx.accounts.position_no;
    let _ = &ctx.accounts.market_quote_vault;
    let market_key = market.key();
    let order_yes_key = order_yes.key();
    let order_no_key = order_no.key();

    require_market_open_for_trading(market, Clock::get()?.unix_timestamp)?;
    require!(order_yes.side == OrderSide::BuyYes, ErrorCode::InvalidSide);
    require!(order_no.side == OrderSide::BuyNo, ErrorCode::InvalidSide);
    require!(
        order_yes.owner != order_no.owner,
        ErrorCode::SelfMatchNotAllowed
    );

    let yes_state = MatchOrderState {
        side: order_yes.side,
        seq: order_yes.seq,
        limit_p_yes_e8: order_yes.limit_p_yes_e8,
        qty_remaining_atoms: order_yes.qty_remaining_atoms,
        escrow_remaining_atoms: order_yes.escrow_remaining_atoms,
        fee_remaining_atoms: order_yes.fee_remaining_atoms,
        taker_cost_basis_atoms: order_yes.taker_cost_basis_atoms,
        protocol_fee_paid_atoms: order_yes.protocol_fee_paid_atoms,
    };
    let no_state = MatchOrderState {
        side: order_no.side,
        seq: order_no.seq,
        limit_p_yes_e8: order_no.limit_p_yes_e8,
        qty_remaining_atoms: order_no.qty_remaining_atoms,
        escrow_remaining_atoms: order_no.escrow_remaining_atoms,
        fee_remaining_atoms: order_no.fee_remaining_atoms,
        taker_cost_basis_atoms: order_no.taker_cost_basis_atoms,
        protocol_fee_paid_atoms: order_no.protocol_fee_paid_atoms,
    };
    let (yes_state, no_state, settlement) =
        settle_crossing_orders(yes_state, no_state, market.protocol_fee_bps, max_qty_atoms)?;

    order_yes.qty_remaining_atoms = yes_state.qty_remaining_atoms;
    order_yes.escrow_remaining_atoms = yes_state.escrow_remaining_atoms;
    order_yes.fee_remaining_atoms = yes_state.fee_remaining_atoms;
    order_yes.taker_cost_basis_atoms = yes_state.taker_cost_basis_atoms;
    order_yes.protocol_fee_paid_atoms = yes_state.protocol_fee_paid_atoms;
    order_no.qty_remaining_atoms = no_state.qty_remaining_atoms;
    order_no.escrow_remaining_atoms = no_state.escrow_remaining_atoms;
    order_no.fee_remaining_atoms = no_state.fee_remaining_atoms;
    order_no.taker_cost_basis_atoms = no_state.taker_cost_basis_atoms;
    order_no.protocol_fee_paid_atoms = no_state.protocol_fee_paid_atoms;
    market.accrued_protocol_fees_atoms = market
        .accrued_protocol_fees_atoms
        .checked_add(settlement.total_protocol_fee_atoms)
        .ok_or(ErrorCode::MathOverflow)?;

    position_yes.pending_refunds_atoms = position_yes
        .pending_refunds_atoms
        .checked_add(settlement.refund_yes_atoms)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_add(settlement.fee_refund_yes_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    position_no.pending_refunds_atoms = position_no
        .pending_refunds_atoms
        .checked_add(settlement.refund_no_atoms)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_add(settlement.fee_refund_no_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    position_yes.yes_shares_atoms = position_yes
        .yes_shares_atoms
        .checked_add(settlement.qty_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    position_no.no_shares_atoms = position_no
        .no_shares_atoms
        .checked_add(settlement.qty_atoms)
        .ok_or(ErrorCode::MathOverflow)?;

    emit!(OrdersMatched {
        market: market_key,
        order_yes: order_yes_key,
        order_no: order_no_key,
        maker_order_seq: settlement.maker_seq,
        taker_side: settlement.taker_side,
        p_exec_e8: settlement.p_exec_e8,
        qty_atoms: settlement.qty_atoms,
        cost_yes_atoms: settlement.cost_yes_atoms,
        cost_no_atoms: settlement.cost_no_atoms,
        refund_yes_atoms: settlement.refund_yes_atoms,
        refund_no_atoms: settlement.refund_no_atoms,
        fee_refund_yes_atoms: settlement.fee_refund_yes_atoms,
        fee_refund_no_atoms: settlement.fee_refund_no_atoms,
        protocol_fee_yes_atoms: settlement.protocol_fee_yes_atoms,
        protocol_fee_no_atoms: settlement.protocol_fee_no_atoms,
    });

    if order_yes.qty_remaining_atoms == 0 {
        market.open_orders_total = market
            .open_orders_total
            .checked_sub(1)
            .ok_or(ErrorCode::MathOverflow)?;
        position_yes.open_orders = position_yes
            .open_orders
            .checked_sub(1)
            .ok_or(ErrorCode::MathOverflow)?;
        order_yes.close(ctx.accounts.owner_yes.to_account_info())?;
    }
    if order_no.qty_remaining_atoms == 0 {
        market.open_orders_total = market
            .open_orders_total
            .checked_sub(1)
            .ok_or(ErrorCode::MathOverflow)?;
        position_no.open_orders = position_no
            .open_orders
            .checked_sub(1)
            .ok_or(ErrorCode::MathOverflow)?;
        order_no.close(ctx.accounts.owner_no.to_account_info())?;
    }
    Ok(())
}
