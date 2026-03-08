// programs/prophet/src/state.rs
use anchor_lang::prelude::*;

pub const PROBABILITY_SCALE: u32 = 100_000_000; // 1e8

/// Maximum number of notaries allowed in a NotaryConfig.
/// Kept small to bound account size and on-chain scanning/lookup.
pub const MAX_NOTARIES: usize = 32;

/// Maximum number of prior instructions to scan for ed25519 verify instructions.
/// This bounds compute in `resolve_market_threshold`.
pub const MAX_ED25519_SCAN: usize = 64;

#[account]
pub struct Market {
    // 32
    pub authority: Pubkey,
    // 32 (legacy single oracle signer; kept for backward compatibility)
    pub oracle_authority: Pubkey,
    // 32
    pub quote_mint: Pubkey,
    // 32
    pub quote_vault: Pubkey,

    // 32 (threshold notary config; Pubkey::default() means not configured)
    pub notary_config: Pubkey,

    // 32 * 3 = 96
    pub resolver_hash: [u8; 32],
    pub proof_hash: [u8; 32],
    pub public_inputs_hash: [u8; 32],

    // 8 * 4 = 32
    pub open_ts: i64,
    pub lock_ts: i64,
    pub resolve_ts: i64,
    pub resolved_ts: i64,

    // 8 * 2 = 16
    pub min_order_qty_atoms: u64,
    pub min_escrow_atoms: u64,

    // 8
    pub next_order_seq: u64,

    // 4
    pub open_orders_total: u32,
    // 4
    pub max_open_orders_total: u32,

    // 2
    pub max_open_orders_per_user: u16,

    // 1
    pub quote_decimals: u8,
    // 1
    pub status: MarketStatus,
    // 1
    pub outcome: MarketOutcome,
    // 1
    pub bump: u8,
}

impl Market {
    // Discriminator (8) + fields.
    //
    // authority(32) + oracle_authority(32) + quote_mint(32) + quote_vault(32)
    // + notary_config(32)
    // + resolver/proof/public_inputs (96)
    // + times (32)
    // + mins (16)
    // + next_order_seq (8)
    // + open_orders_total (4) + max_open_orders_total (4)
    // + max_open_orders_per_user (2)
    // + quote_decimals/status/outcome/bump (4)
    //
    // Total fields = 324 bytes; allocate 336 bytes for headroom/alignment.
    pub const LEN: usize = 336;
}

#[account]
pub struct NotaryConfig {
    pub admin: Pubkey, // 32
    pub threshold: u8, // 1
    pub notary_count: u8, // 1
    pub bump: u8, // 1
    pub _reserved0: [u8; 5], // 5 (padding + future flags)
    pub version: u64, // 8
    pub notary_keys: [Pubkey; MAX_NOTARIES], // MAX_NOTARIES * 32
}

impl NotaryConfig {
    // 32 + 1 + 1 + 1 + 5 + 8 + 32*MAX_NOTARIES
    pub const LEN: usize = 32 + 1 + 1 + 1 + 5 + 8 + 32 * MAX_NOTARIES;

    pub fn contains_notary(&self, pk: &Pubkey) -> bool {
        let n = self.notary_count as usize;
        if n > MAX_NOTARIES {
            return false;
        }
        self.notary_keys[..n].iter().any(|x| x == pk)
    }
}

#[account]
pub struct Order {
    pub market: Pubkey,
    pub owner: Pubkey,
    pub side: OrderSide,
    pub seq: u64,
    pub limit_p_yes_e8: u32,
    pub qty_remaining_atoms: u64,
    pub escrow_remaining_atoms: u64,
    pub created_ts: i64,
}

impl Order {
    pub const LEN: usize = 128;
}

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

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum MarketStatus {
    Open,
    Locked,
    Resolved,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum MarketOutcome {
    Undecided,
    Yes,
    No,
    Invalid,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum OrderSide {
    BuyYes,
    BuyNo,
}
