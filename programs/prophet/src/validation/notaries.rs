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

pub(crate) fn notary_config_snapshot_pda(
    admin: &Pubkey,
    version: u64,
    program_id: &Pubkey,
) -> Result<(Pubkey, u8)> {
    require!(version > 0, ErrorCode::InvalidNotaryConfigVersion);
    if version == 1 {
        Ok(Pubkey::find_program_address(
            &[b"notary_config", admin.as_ref()],
            program_id,
        ))
    } else {
        let version_bytes = version.to_le_bytes();
        Ok(Pubkey::find_program_address(
            &[b"notary_config", admin.as_ref(), &version_bytes],
            program_id,
        ))
    }
}

pub(crate) fn validate_notary_config_snapshot_address(
    config_key: &Pubkey,
    config: &NotaryConfig,
    program_id: &Pubkey,
) -> Result<()> {
    let (expected_key, expected_bump) =
        notary_config_snapshot_pda(&config.admin, config.version, program_id)?;
    require_keys_eq!(
        *config_key,
        expected_key,
        ErrorCode::InvalidNotaryConfigSnapshot
    );
    require!(
        config.bump == expected_bump,
        ErrorCode::InvalidNotaryConfigSnapshot
    );
    Ok(())
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
    require!(config.version > 0, ErrorCode::InvalidNotaryConfigVersion);
    let count = config.notary_count as usize;
    require!(count <= MAX_NOTARIES, ErrorCode::InvalidNotarySet);
    validate_notary_set(config.threshold, &config.notary_keys[..count])
}

/// Market V2 is deliberately narrower than the future-facing NotaryConfig
/// account.  The operated resolution stack has exactly two independent roles.
pub(crate) fn validate_market_v2_notary_config(config: &NotaryConfig) -> Result<()> {
    validate_stored_notary_config(config)?;
    require!(config.threshold == 2, ErrorCode::UnsupportedNotaryTopology);
    require!(
        config.notary_count == 2,
        ErrorCode::UnsupportedNotaryTopology
    );
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

    #[test]
    fn snapshot_pda_preserves_legacy_v1_and_versions_successors() {
        let admin = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        let (legacy, _) =
            Pubkey::find_program_address(&[b"notary_config", admin.as_ref()], &program_id);
        let (v1, _) = notary_config_snapshot_pda(&admin, 1, &program_id).unwrap();
        let (v2, _) = notary_config_snapshot_pda(&admin, 2, &program_id).unwrap();
        let (v3, _) = notary_config_snapshot_pda(&admin, 3, &program_id).unwrap();

        assert_eq!(v1, legacy);
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert!(notary_config_snapshot_pda(&admin, 0, &program_id).is_err());
    }

    #[test]
    fn market_v2_accepts_only_exact_two_of_two() {
        let mut config = NotaryConfig {
            admin: Pubkey::new_unique(),
            threshold: 2,
            notary_count: 2,
            bump: 1,
            _reserved0: [0; 5],
            version: 1,
            notary_keys: [Pubkey::default(); MAX_NOTARIES],
        };
        config.notary_keys[0] = Pubkey::new_unique();
        config.notary_keys[1] = Pubkey::new_unique();
        assert!(validate_market_v2_notary_config(&config).is_ok());
        for (threshold, count) in [(1, 2), (1, 3), (2, 3), (3, 3)] {
            config.threshold = threshold;
            config.notary_count = count;
            if count == 3 {
                config.notary_keys[2] = Pubkey::new_unique();
            }
            assert!(validate_market_v2_notary_config(&config).is_err());
        }
        config.threshold = 2;
        config.notary_count = 2;
        config.notary_keys[1] = config.notary_keys[0];
        assert!(validate_market_v2_notary_config(&config).is_err());
        config.notary_keys[1] = Pubkey::default();
        assert!(validate_market_v2_notary_config(&config).is_err());
        config.notary_count = (MAX_NOTARIES as u8) + 1;
        assert!(validate_market_v2_notary_config(&config).is_err());
    }
}
