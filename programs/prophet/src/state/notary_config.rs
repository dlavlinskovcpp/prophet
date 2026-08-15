use super::MAX_NOTARIES;
use anchor_lang::prelude::*;

#[account]
pub struct NotaryConfig {
    pub admin: Pubkey,
    pub threshold: u8,
    pub notary_count: u8,
    pub bump: u8,
    pub _reserved0: [u8; 5],
    pub version: u64,
    pub notary_keys: [Pubkey; MAX_NOTARIES],
}

impl NotaryConfig {
    pub const LEN: usize = 32 + 1 + 1 + 1 + 5 + 8 + 32 * MAX_NOTARIES;

    pub fn contains_notary(&self, pubkey: &Pubkey) -> bool {
        let count = self.notary_count as usize;
        if count > MAX_NOTARIES {
            return false;
        }
        self.notary_keys[..count].iter().any(|key| key == pubkey)
    }
}
