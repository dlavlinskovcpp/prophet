//! Host-only entrypoints for `cargo fuzz`.
//!
//! They make the pure economic calculations fuzzable without widening the
//! deployed instruction surface. A panic represents an invariant violation.

use crate::{
    math::{
        mul_div_ceil, mul_div_floor, protocol_fee_ceil, required_escrow_atoms,
        settle_crossing_orders, MatchOrderState,
    },
    state::{OrderSide, PROBABILITY_SCALE},
};

fn u64_at(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset + index).copied().unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

/// Differential-check multiplication and division against a u128 reference.
pub fn fuzz_arithmetic(data: &[u8]) {
    let a = u64_at(data, 0);
    let b = u64_at(data, 8);
    let denominator = u64_at(data, 16);
    if denominator == 0 {
        assert!(mul_div_floor(a, b, denominator).is_err());
        assert!(mul_div_ceil(a, b, denominator).is_err());
        return;
    }

    let numerator = u128::from(a) * u128::from(b);
    let denominator_u128 = u128::from(denominator);
    let floor = numerator / denominator_u128;
    let ceil = if numerator == 0 {
        0
    } else {
        (numerator + denominator_u128 - 1) / denominator_u128
    };
    if floor > u128::from(u64::MAX) {
        assert!(mul_div_floor(a, b, denominator).is_err());
    } else {
        assert_eq!(mul_div_floor(a, b, denominator).unwrap(), floor as u64);
    }
    if ceil > u128::from(u64::MAX) {
        assert!(mul_div_ceil(a, b, denominator).is_err());
    } else {
        assert_eq!(mul_div_ceil(a, b, denominator).unwrap(), ceil as u64);
    }
}

/// Check settlement conservation for arbitrary, but valid, crossing orders.
pub fn fuzz_settlement(data: &[u8]) {
    let fee_bps = (u64_at(data, 0) % 1_001) as u16;
    let no_limit = (u64_at(data, 8) % (u64::from(PROBABILITY_SCALE) + 1)) as u32;
    let yes_limit =
        no_limit + (u64_at(data, 16) % u64::from(PROBABILITY_SCALE - no_limit + 1)) as u32;
    let yes_qty = 1 + u64_at(data, 24) % 4_096;
    let no_qty = 1 + u64_at(data, 32) % 4_096;
    let yes_maker = data.get(40).copied().unwrap_or(0) & 1 == 0;
    let yes_escrow = required_escrow_atoms(OrderSide::BuyYes, yes_qty, yes_limit).unwrap();
    let no_escrow = required_escrow_atoms(OrderSide::BuyNo, no_qty, no_limit).unwrap();
    let yes = MatchOrderState {
        side: OrderSide::BuyYes,
        seq: if yes_maker { 1 } else { 2 },
        limit_p_yes_e8: yes_limit,
        qty_remaining_atoms: yes_qty,
        escrow_remaining_atoms: yes_escrow,
        fee_remaining_atoms: protocol_fee_ceil(yes_escrow, fee_bps).unwrap(),
        taker_cost_basis_atoms: 0,
        protocol_fee_paid_atoms: 0,
    };
    let no = MatchOrderState {
        side: OrderSide::BuyNo,
        seq: if yes_maker { 2 } else { 1 },
        limit_p_yes_e8: no_limit,
        qty_remaining_atoms: no_qty,
        escrow_remaining_atoms: no_escrow,
        fee_remaining_atoms: protocol_fee_ceil(no_escrow, fee_bps).unwrap(),
        taker_cost_basis_atoms: 0,
        protocol_fee_paid_atoms: 0,
    };
    let max_qty = 1 + u64_at(data, 41) % yes_qty.min(no_qty);
    let before = u128::from(yes.escrow_remaining_atoms)
        + u128::from(yes.fee_remaining_atoms)
        + u128::from(no.escrow_remaining_atoms)
        + u128::from(no.fee_remaining_atoms);

    if let Ok((yes_after, no_after, settlement)) = settle_crossing_orders(yes, no, fee_bps, max_qty)
    {
        let after = u128::from(yes_after.escrow_remaining_atoms)
            + u128::from(yes_after.fee_remaining_atoms)
            + u128::from(no_after.escrow_remaining_atoms)
            + u128::from(no_after.fee_remaining_atoms)
            + u128::from(settlement.refund_yes_atoms)
            + u128::from(settlement.refund_no_atoms)
            + u128::from(settlement.fee_refund_yes_atoms)
            + u128::from(settlement.fee_refund_no_atoms)
            + u128::from(settlement.total_protocol_fee_atoms)
            + u128::from(settlement.qty_atoms);
        assert_eq!(before, after);
        assert_eq!(
            settlement.cost_yes_atoms + settlement.cost_no_atoms,
            settlement.qty_atoms
        );
    }
}
