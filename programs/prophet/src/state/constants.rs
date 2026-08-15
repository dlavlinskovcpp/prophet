pub const PROBABILITY_SCALE: u32 = 100_000_000;
pub const MAX_PROTOCOL_FEE_BPS: u16 = 1_000;

/// Maximum number of notaries allowed in a notary configuration.
pub const MAX_NOTARIES: usize = 32;

/// Canonical V2 resolution uses one self-contained Ed25519 instruction per
/// signature. With the 235-byte signed message and legacy 1,232-byte Solana
/// transaction limit, at most two signatures fit alongside the resolve call.
pub const MAX_NOTARY_THRESHOLD: u8 = 2;

/// Maximum number of prior instructions inspected during threshold resolution.
pub const MAX_ED25519_SCAN: usize = 16;
