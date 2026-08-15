use anchor_lang::prelude::*;

#[account]
pub struct Position {
    pub market: Pubkey,
    pub owner: Pubkey,
    pub yes_shares_atoms: u64,
    pub no_shares_atoms: u64,
    pub pending_refunds_atoms: u64,
    pub open_orders: u16,
    pub redeemed: bool,
}

impl Position {
    pub const LEN: usize = 128;
}
