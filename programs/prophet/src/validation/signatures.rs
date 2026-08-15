use crate::{
    errors::ErrorCode,
    state::{NotaryConfig, MAX_ED25519_SCAN},
};
use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};
use solana_sdk_ids::ed25519_program::ID as ED25519_ID_NATIVE;

/// Validates the bounded set of preceding native Ed25519 instructions and
/// returns the number of distinct authorized signatures over `expected_message`.
pub(crate) fn count_valid_notary_signatures(
    instructions_sysvar: &AccountInfo,
    config: &NotaryConfig,
    expected_message: &[u8],
) -> Result<u8> {
    let current_index = load_current_index_checked(instructions_sysvar)?;
    require!(current_index > 0, ErrorCode::MissingEd25519Ix);

    let mut seen = Vec::with_capacity(config.threshold as usize);
    let mut valid_count = 0_u8;
    let mut scanned = 0_u16;
    let mut index = (current_index as i32) - 1;

    while index >= 0 && scanned < MAX_ED25519_SCAN as u16 && valid_count < config.threshold {
        let instruction = load_instruction_at_checked(index as usize, instructions_sysvar)?;
        scanned = scanned.saturating_add(1);
        index -= 1;

        if instruction.program_id.to_bytes() != ED25519_ID_NATIVE.to_bytes() {
            continue;
        }

        let data = &instruction.data;
        if data.len() < 16 || data[0] != 1 || data[1] != 0 {
            continue;
        }

        let signature_offset = read_u16(data, 2)?;
        let signature_instruction = read_u16(data, 4)?;
        let public_key_offset = read_u16(data, 6)?;
        let public_key_instruction = read_u16(data, 8)?;
        let message_offset = read_u16(data, 10)?;
        let message_size = read_u16(data, 12)?;
        let message_instruction = read_u16(data, 14)?;

        require!(
            signature_instruction == u16::MAX,
            ErrorCode::Ed25519IxIndexesNotSelf
        );
        require!(
            public_key_instruction == u16::MAX,
            ErrorCode::Ed25519IxIndexesNotSelf
        );
        require!(
            message_instruction == u16::MAX,
            ErrorCode::Ed25519IxIndexesNotSelf
        );

        let signature_end = checked_end(signature_offset, 64)?;
        let public_key_end = checked_end(public_key_offset, 32)?;
        let message_end = checked_end(message_offset, message_size as usize)?;
        if signature_end > data.len() || public_key_end > data.len() || message_end > data.len() {
            continue;
        }

        let public_key = Pubkey::new_from_array(
            data[public_key_offset as usize..public_key_end]
                .try_into()
                .map_err(|_| ErrorCode::InvalidEd25519Data)?,
        );
        if !config.contains_notary(&public_key) {
            continue;
        }
        if seen.contains(&public_key) {
            return Err(ErrorCode::DuplicateNotarySig.into());
        }
        if &data[message_offset as usize..message_end] != expected_message {
            continue;
        }

        seen.push(public_key);
        valid_count = valid_count.saturating_add(1);
    }

    Ok(valid_count)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data[offset..offset + 2]
            .try_into()
            .map_err(|_| ErrorCode::InvalidEd25519Data)?,
    ))
}

fn checked_end(offset: u16, length: usize) -> Result<usize> {
    (offset as usize)
        .checked_add(length)
        .ok_or_else(|| ErrorCode::InvalidEd25519Data.into())
}
