use crate::{
    errors::ErrorCode,
    state::{NotaryConfig, MAX_NOTARIES, MAX_NOTARY_THRESHOLD},
};
use anchor_lang::prelude::*;

pub(crate) fn validate_notary_set(threshold: u8, notary_keys: &[Pubkey]) -> Result<()> {
    require!(!notary_keys.is_empty(), ErrorCode::InvalidNotarySet);
    require!(
        notary_keys.len() <= MAX_NOTARIES,
        ErrorCode::InvalidNotarySet
    );
    require!(threshold > 0, ErrorCode::InvalidNotaryThreshold);
    require!(
        threshold <= MAX_NOTARY_THRESHOLD,
        ErrorCode::InvalidNotaryThreshold
    );
    require!(
        (threshold as usize) <= notary_keys.len(),
        ErrorCode::InvalidNotaryThreshold
    );

    for (index, key) in notary_keys.iter().enumerate() {
        require!(*key != Pubkey::default(), ErrorCode::InvalidNotarySet);
        require!(
            !notary_keys[index + 1..].contains(key),
            ErrorCode::DuplicateNotaryKey
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unusable_thresholds_and_keys() {
        let keys = [
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ];
        assert!(validate_notary_set(MAX_NOTARY_THRESHOLD + 1, &keys).is_err());
        assert!(validate_notary_set(1, &[Pubkey::default()]).is_err());
    }
}

pub(crate) fn replace_notary_keys(
    stored_keys: &mut [Pubkey; MAX_NOTARIES],
    previous_count: usize,
    notary_keys: &[Pubkey],
) {
    stored_keys[..previous_count.min(MAX_NOTARIES)].fill(Pubkey::default());
    stored_keys[..notary_keys.len()].copy_from_slice(notary_keys);
}

pub(crate) fn validate_stored_notary_config(config: &NotaryConfig) -> Result<()> {
    let count = config.notary_count as usize;
    require!(count <= MAX_NOTARIES, ErrorCode::InvalidNotarySet);
    validate_notary_set(config.threshold, &config.notary_keys[..count])
}
