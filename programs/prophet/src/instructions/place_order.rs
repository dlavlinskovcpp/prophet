use crate::{
    errors::ErrorCode,
    events::OrderPlaced,
    math::{protocol_fee_ceil, required_escrow_atoms},
    state::{Market, Order, OrderSide, Position, PROBABILITY_SCALE},
    validation::require_market_open_for_trading,
};
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[derive(Accounts)]
#[instruction(order_seq: u64)]
pub struct PlaceOrder<'info> {
    #[account(
        mut,
        seeds = [b"market", market.creator.as_ref(), market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes(), &market.market_nonce.to_le_bytes()],
        bump = market.bump
    )]
    pub market: Box<Account<'info, Market>>,
    #[account(
        init,
        payer = owner,
        space = 8 + Order::LEN,
        seeds = [b"order", market.key().as_ref(), owner.key().as_ref(), &order_seq.to_le_bytes()],
        bump
    )]
    pub order: Box<Account<'info, Order>>,
    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + Position::LEN,
        seeds = [b"position", market.key().as_ref(), owner.key().as_ref()],
        bump,
        constraint = (
            position.market == Pubkey::default() && position.owner == Pubkey::default()
        ) || (
            position.market == market.key() && position.owner == owner.key()
        ) @ ErrorCode::InvalidMarket
    )]
    pub position: Box<Account<'info, Position>>,
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        constraint = owner_quote_ata.mint == market.quote_mint,
        constraint = owner_quote_ata.owner == owner.key()
    )]
    pub owner_quote_ata: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        constraint = quote_vault.key() == market.quote_vault,
        constraint = quote_vault.mint == market.quote_mint,
        constraint = quote_vault.owner == market.key()
    )]
    pub quote_vault: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub(crate) fn place_order(
    ctx: Context<PlaceOrder>,
    order_seq: u64,
    side: OrderSide,
    limit_p_yes_e8: u32,
    qty_atoms: u64,
) -> Result<()> {
    let market = &mut ctx.accounts.market;
    let order = &mut ctx.accounts.order;
    let position = &mut ctx.accounts.position;
    let owner = &ctx.accounts.owner;
    let market_key = market.key();
    let owner_key = owner.key();
    let order_key = order.key();
    let now = Clock::get()?.unix_timestamp;

    require_market_open_for_trading(market, now)?;
    require!(
        order_seq == market.next_order_seq,
        ErrorCode::InvalidOrderSeq
    );
    require!(
        qty_atoms >= market.min_order_qty_atoms,
        ErrorCode::OrderQtyTooSmall
    );
    require!(
        limit_p_yes_e8 <= PROBABILITY_SCALE,
        ErrorCode::InvalidProbability
    );
    require!(
        position.open_orders < market.max_open_orders_per_user,
        ErrorCode::UserOpenOrdersLimit
    );
    require!(
        market.open_orders_total < market.max_open_orders_total,
        ErrorCode::GlobalOpenOrdersLimit
    );

    let escrow_atoms = required_escrow_atoms(side, qty_atoms, limit_p_yes_e8)?;
    let fee_reserve_atoms = protocol_fee_ceil(escrow_atoms, market.protocol_fee_bps)?;
    let total_deposit_atoms = escrow_atoms
        .checked_add(fee_reserve_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    require!(
        escrow_atoms >= market.min_escrow_atoms,
        ErrorCode::EscrowTooSmall
    );

    token::transfer(
        CpiContext::new(
            Token::id(),
            Transfer {
                from: ctx.accounts.owner_quote_ata.to_account_info(),
                to: ctx.accounts.quote_vault.to_account_info(),
                authority: owner.to_account_info(),
            },
        ),
        total_deposit_atoms,
    )?;

    order.market = market_key;
    order.owner = owner_key;
    order.side = side;
    order.seq = order_seq;
    order.limit_p_yes_e8 = limit_p_yes_e8;
    order.qty_remaining_atoms = qty_atoms;
    order.escrow_remaining_atoms = escrow_atoms;
    order.fee_remaining_atoms = fee_reserve_atoms;
    order.created_ts = now;
    if position.market == Pubkey::default() {
        position.market = market_key;
        position.owner = owner_key;
    }
    position.open_orders = position
        .open_orders
        .checked_add(1)
        .ok_or(ErrorCode::MathOverflow)?;
    market.next_order_seq = market
        .next_order_seq
        .checked_add(1)
        .ok_or(ErrorCode::MathOverflow)?;
    market.open_orders_total = market
        .open_orders_total
        .checked_add(1)
        .ok_or(ErrorCode::MathOverflow)?;

    emit!(OrderPlaced {
        market: market_key,
        order: order_key,
        owner: owner_key,
        side,
        seq: order_seq,
        limit_p_yes_e8,
        qty_atoms,
        escrow_atoms,
        fee_reserve_atoms,
    });
    Ok(())
}
