use super::{mul_div_ceil, mul_div_floor};
use anchor_lang::prelude::*;

const BPS_SCALE: u64 = 10_000;

pub(crate) fn protocol_fee_floor(amount_atoms: u64, fee_bps: u16) -> Result<u64> {
    mul_div_floor(amount_atoms, u64::from(fee_bps), BPS_SCALE)
}

pub(crate) fn protocol_fee_ceil(amount_atoms: u64, fee_bps: u16) -> Result<u64> {
    mul_div_ceil(amount_atoms, u64::from(fee_bps), BPS_SCALE)
}
