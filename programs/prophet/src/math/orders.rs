use super::{mul_div_ceil, mul_div_floor, protocol_fee_floor};
use crate::{
    errors::ErrorCode,
    state::{OrderSide, PROBABILITY_SCALE},
};
use anchor_lang::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatchOrderState {
    pub side: OrderSide,
    pub seq: u64,
    pub limit_p_yes_e8: u32,
    pub qty_remaining_atoms: u64,
    pub escrow_remaining_atoms: u64,
    pub fee_remaining_atoms: u64,
    pub taker_cost_basis_atoms: u64,
    pub protocol_fee_paid_atoms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatchSettlement {
    pub maker_seq: u64,
    pub taker_side: OrderSide,
    pub p_exec_e8: u32,
    pub qty_atoms: u64,
    pub cost_yes_atoms: u64,
    pub cost_no_atoms: u64,
    pub refund_yes_atoms: u64,
    pub refund_no_atoms: u64,
    pub fee_refund_yes_atoms: u64,
    pub fee_refund_no_atoms: u64,
    pub protocol_fee_yes_atoms: u64,
    pub protocol_fee_no_atoms: u64,
    pub total_protocol_fee_atoms: u64,
}

pub(crate) fn required_escrow_atoms(
    side: OrderSide,
    qty_atoms: u64,
    limit_p_yes_e8: u32,
) -> Result<u64> {
    match side {
        OrderSide::BuyYes => mul_div_ceil(
            qty_atoms,
            u64::from(limit_p_yes_e8),
            u64::from(PROBABILITY_SCALE),
        ),
        OrderSide::BuyNo => {
            let p_no = PROBABILITY_SCALE
                .checked_sub(limit_p_yes_e8)
                .ok_or(ErrorCode::MathOverflow)?;
            mul_div_ceil(qty_atoms, u64::from(p_no), u64::from(PROBABILITY_SCALE))
        }
    }
}

/// Pure settlement calculation. Account mutation is deliberately kept in the
/// instruction layer so auditors can review value movement independently.
pub(crate) fn settle_crossing_orders(
    mut order_yes: MatchOrderState,
    mut order_no: MatchOrderState,
    protocol_fee_bps: u16,
    max_qty_atoms: u64,
) -> Result<(MatchOrderState, MatchOrderState, MatchSettlement)> {
    require!(order_yes.side == OrderSide::BuyYes, ErrorCode::InvalidSide);
    require!(order_no.side == OrderSide::BuyNo, ErrorCode::InvalidSide);
    require!(
        order_yes.limit_p_yes_e8 <= PROBABILITY_SCALE,
        ErrorCode::InvalidProbability
    );
    require!(
        order_no.limit_p_yes_e8 <= PROBABILITY_SCALE,
        ErrorCode::InvalidProbability
    );
    require!(
        order_yes.limit_p_yes_e8 >= order_no.limit_p_yes_e8,
        ErrorCode::NoCross
    );

    let (maker_seq, p_exec_e8, taker_side) = if order_yes.seq < order_no.seq {
        (order_yes.seq, order_yes.limit_p_yes_e8, OrderSide::BuyNo)
    } else {
        (order_no.seq, order_no.limit_p_yes_e8, OrderSide::BuyYes)
    };

    let qty_atoms = max_qty_atoms.min(
        order_yes
            .qty_remaining_atoms
            .min(order_no.qty_remaining_atoms),
    );
    require!(qty_atoms > 0, ErrorCode::ZeroMatchQty);

    let escrow_yes_after = required_escrow_atoms(
        order_yes.side,
        order_yes
            .qty_remaining_atoms
            .checked_sub(qty_atoms)
            .ok_or(ErrorCode::MathOverflow)?,
        order_yes.limit_p_yes_e8,
    )?;
    let escrow_no_after = required_escrow_atoms(
        order_no.side,
        order_no
            .qty_remaining_atoms
            .checked_sub(qty_atoms)
            .ok_or(ErrorCode::MathOverflow)?,
        order_no.limit_p_yes_e8,
    )?;
    let release_yes_total = order_yes
        .escrow_remaining_atoms
        .checked_sub(escrow_yes_after)
        .ok_or(ErrorCode::InsufficientEscrow)?;
    let release_no_total = order_no
        .escrow_remaining_atoms
        .checked_sub(escrow_no_after)
        .ok_or(ErrorCode::InsufficientEscrow)?;
    require!(
        release_yes_total
            .checked_add(release_no_total)
            .ok_or(ErrorCode::MathOverflow)?
            >= qty_atoms,
        ErrorCode::MatchQtyTooSmallForRounding
    );

    let target_cost_yes_atoms = mul_div_floor(
        qty_atoms,
        u64::from(p_exec_e8),
        u64::from(PROBABILITY_SCALE),
    )?;
    let min_cost_yes_atoms = qty_atoms.saturating_sub(release_no_total);
    let max_cost_yes_atoms = release_yes_total.min(qty_atoms);
    require!(
        min_cost_yes_atoms <= max_cost_yes_atoms,
        ErrorCode::MatchQtyTooSmallForRounding
    );
    let cost_yes_atoms = target_cost_yes_atoms.clamp(min_cost_yes_atoms, max_cost_yes_atoms);
    let cost_no_atoms = qty_atoms
        .checked_sub(cost_yes_atoms)
        .ok_or(ErrorCode::MathOverflow)?;

    let protocol_fee_yes_atoms = if taker_side == OrderSide::BuyYes {
        accrue_taker_fee(&mut order_yes, cost_yes_atoms, protocol_fee_bps)?
    } else {
        0
    };
    let protocol_fee_no_atoms = if taker_side == OrderSide::BuyNo {
        accrue_taker_fee(&mut order_no, cost_no_atoms, protocol_fee_bps)?
    } else {
        0
    };
    let total_protocol_fee_atoms = protocol_fee_yes_atoms
        .checked_add(protocol_fee_no_atoms)
        .ok_or(ErrorCode::MathOverflow)?;

    order_yes.qty_remaining_atoms = order_yes
        .qty_remaining_atoms
        .checked_sub(qty_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    order_yes.escrow_remaining_atoms = order_yes
        .escrow_remaining_atoms
        .checked_sub(cost_yes_atoms)
        .ok_or(ErrorCode::InsufficientEscrow)?;
    order_yes.fee_remaining_atoms = order_yes
        .fee_remaining_atoms
        .checked_sub(protocol_fee_yes_atoms)
        .ok_or(ErrorCode::InsufficientEscrow)?;

    order_no.qty_remaining_atoms = order_no
        .qty_remaining_atoms
        .checked_sub(qty_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    order_no.escrow_remaining_atoms = order_no
        .escrow_remaining_atoms
        .checked_sub(cost_no_atoms)
        .ok_or(ErrorCode::InsufficientEscrow)?;
    order_no.fee_remaining_atoms = order_no
        .fee_remaining_atoms
        .checked_sub(protocol_fee_no_atoms)
        .ok_or(ErrorCode::InsufficientEscrow)?;

    let refund_yes_atoms = release_yes_total
        .checked_sub(cost_yes_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    let refund_no_atoms = release_no_total
        .checked_sub(cost_no_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    order_yes.escrow_remaining_atoms = escrow_yes_after;
    order_no.escrow_remaining_atoms = escrow_no_after;

    let fee_refund_yes_atoms = if order_yes.qty_remaining_atoms == 0 {
        let refund = order_yes.fee_remaining_atoms;
        order_yes.fee_remaining_atoms = 0;
        refund
    } else {
        0
    };
    let fee_refund_no_atoms = if order_no.qty_remaining_atoms == 0 {
        let refund = order_no.fee_remaining_atoms;
        order_no.fee_remaining_atoms = 0;
        refund
    } else {
        0
    };

    let settlement = MatchSettlement {
        maker_seq,
        taker_side,
        p_exec_e8,
        qty_atoms,
        cost_yes_atoms,
        cost_no_atoms,
        refund_yes_atoms,
        refund_no_atoms,
        fee_refund_yes_atoms,
        fee_refund_no_atoms,
        protocol_fee_yes_atoms,
        protocol_fee_no_atoms,
        total_protocol_fee_atoms,
    };

    Ok((order_yes, order_no, settlement))
}

/// Charges only the delta between the fee due on the cumulative taker cost and
/// the amount already paid. This makes fees invariant to fill fragmentation.
fn accrue_taker_fee(
    order: &mut MatchOrderState,
    fill_cost_atoms: u64,
    protocol_fee_bps: u16,
) -> Result<u64> {
    let new_cost_basis = order
        .taker_cost_basis_atoms
        .checked_add(fill_cost_atoms)
        .ok_or(ErrorCode::MathOverflow)?;
    let total_fee_due = protocol_fee_floor(new_cost_basis, protocol_fee_bps)?;
    let incremental_fee = total_fee_due
        .checked_sub(order.protocol_fee_paid_atoms)
        .ok_or(ErrorCode::MathOverflow)?;

    order.taker_cost_basis_atoms = new_cost_basis;
    order.protocol_fee_paid_atoms = total_fee_due;
    Ok(incremental_fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{math::protocol_fee_ceil, state::MAX_PROTOCOL_FEE_BPS};

    fn reserve_for_order(
        side: OrderSide,
        qty_atoms: u64,
        limit_p_yes_e8: u32,
        fee_bps: u16,
    ) -> u64 {
        let escrow = required_escrow_atoms(side, qty_atoms, limit_p_yes_e8).unwrap();
        protocol_fee_ceil(escrow, fee_bps).unwrap()
    }

    #[test]
    fn fee_reserve_covers_sampled_worst_case_taker_fees() {
        let quantities = [1_u64, 2, 3, 7, 10, 37, 99, 100, 101, 10_000];
        let limits = [
            0_u32,
            1,
            1_000_000,
            25_000_000,
            50_000_000,
            75_000_000,
            PROBABILITY_SCALE - 1,
            PROBABILITY_SCALE,
        ];
        let fee_rates = [0_u16, 1, 5, 50, 250, 500, MAX_PROTOCOL_FEE_BPS];

        for fee_bps in fee_rates {
            for qty_atoms in quantities {
                for limit in limits {
                    let yes_reserve =
                        reserve_for_order(OrderSide::BuyYes, qty_atoms, limit, fee_bps);
                    for execution_price in [0_u32, limit / 2, limit] {
                        let yes_cost = mul_div_floor(
                            qty_atoms,
                            u64::from(execution_price),
                            u64::from(PROBABILITY_SCALE),
                        )
                        .unwrap();
                        assert!(protocol_fee_floor(yes_cost, fee_bps).unwrap() <= yes_reserve);
                    }

                    let no_reserve = reserve_for_order(OrderSide::BuyNo, qty_atoms, limit, fee_bps);
                    for execution_price in [
                        limit,
                        limit + (PROBABILITY_SCALE - limit) / 2,
                        limit.saturating_add(1).min(PROBABILITY_SCALE),
                        PROBABILITY_SCALE,
                    ] {
                        let yes_cost = mul_div_floor(
                            qty_atoms,
                            u64::from(execution_price),
                            u64::from(PROBABILITY_SCALE),
                        )
                        .unwrap();
                        assert!(
                            protocol_fee_floor(qty_atoms - yes_cost, fee_bps).unwrap()
                                <= no_reserve
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn settlement_sweep_conserves_value_and_charges_only_taker() {
        let yes_limits = [1_u32, 10_000_000, 40_000_000, 50_000_000, 60_000_000];
        let no_limits = [0_u32, 1, 10_000_000, 40_000_000, 50_000_000];
        let quantities = [1_u64, 2, 3, 7, 10, 25, 100];
        let maximums = [1_u64, 2, 5, 10, 100];
        let fee_rates = [0_u16, 1, 50, 500, MAX_PROTOCOL_FEE_BPS];

        for fee_bps in fee_rates {
            for yes_limit in yes_limits {
                for no_limit in no_limits {
                    if yes_limit < no_limit {
                        continue;
                    }
                    for yes_qty in quantities {
                        for no_qty in quantities {
                            for max_qty in maximums {
                                for yes_is_maker in [true, false] {
                                    let yes_escrow = required_escrow_atoms(
                                        OrderSide::BuyYes,
                                        yes_qty,
                                        yes_limit,
                                    )
                                    .unwrap();
                                    let no_escrow =
                                        required_escrow_atoms(OrderSide::BuyNo, no_qty, no_limit)
                                            .unwrap();
                                    let yes = MatchOrderState {
                                        side: OrderSide::BuyYes,
                                        seq: if yes_is_maker { 1 } else { 2 },
                                        limit_p_yes_e8: yes_limit,
                                        qty_remaining_atoms: yes_qty,
                                        escrow_remaining_atoms: yes_escrow,
                                        fee_remaining_atoms: protocol_fee_ceil(yes_escrow, fee_bps)
                                            .unwrap(),
                                        taker_cost_basis_atoms: 0,
                                        protocol_fee_paid_atoms: 0,
                                    };
                                    let no = MatchOrderState {
                                        side: OrderSide::BuyNo,
                                        seq: if yes_is_maker { 2 } else { 1 },
                                        limit_p_yes_e8: no_limit,
                                        qty_remaining_atoms: no_qty,
                                        escrow_remaining_atoms: no_escrow,
                                        fee_remaining_atoms: protocol_fee_ceil(no_escrow, fee_bps)
                                            .unwrap(),
                                        taker_cost_basis_atoms: 0,
                                        protocol_fee_paid_atoms: 0,
                                    };
                                    let before = yes.escrow_remaining_atoms
                                        + yes.fee_remaining_atoms
                                        + no.escrow_remaining_atoms
                                        + no.fee_remaining_atoms;
                                    let requested = max_qty.min(yes_qty.min(no_qty));
                                    let released = yes_escrow
                                        - required_escrow_atoms(
                                            OrderSide::BuyYes,
                                            yes_qty - requested,
                                            yes_limit,
                                        )
                                        .unwrap()
                                        + no_escrow
                                        - required_escrow_atoms(
                                            OrderSide::BuyNo,
                                            no_qty - requested,
                                            no_limit,
                                        )
                                        .unwrap();

                                    let (yes_after, no_after, settlement) =
                                        match settle_crossing_orders(yes, no, fee_bps, max_qty) {
                                            Ok(result) => result,
                                            Err(error) => {
                                                assert!(released < requested, "{error}");
                                                continue;
                                            }
                                        };
                                    let after = yes_after.escrow_remaining_atoms
                                        + yes_after.fee_remaining_atoms
                                        + no_after.escrow_remaining_atoms
                                        + no_after.fee_remaining_atoms
                                        + settlement.refund_yes_atoms
                                        + settlement.refund_no_atoms
                                        + settlement.fee_refund_yes_atoms
                                        + settlement.fee_refund_no_atoms
                                        + settlement.total_protocol_fee_atoms
                                        + settlement.qty_atoms;

                                    assert_eq!(before, after);
                                    assert_eq!(
                                        settlement.cost_yes_atoms + settlement.cost_no_atoms,
                                        settlement.qty_atoms
                                    );
                                    match settlement.taker_side {
                                        OrderSide::BuyYes => {
                                            assert_eq!(settlement.protocol_fee_no_atoms, 0)
                                        }
                                        OrderSide::BuyNo => {
                                            assert_eq!(settlement.protocol_fee_yes_atoms, 0)
                                        }
                                    }
                                    assert_eq!(
                                        yes_after.escrow_remaining_atoms,
                                        required_escrow_atoms(
                                            OrderSide::BuyYes,
                                            yes_after.qty_remaining_atoms,
                                            yes_limit,
                                        )
                                        .unwrap()
                                    );
                                    assert_eq!(
                                        no_after.escrow_remaining_atoms,
                                        required_escrow_atoms(
                                            OrderSide::BuyNo,
                                            no_after.qty_remaining_atoms,
                                            no_limit,
                                        )
                                        .unwrap()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn taker_fee_is_invariant_to_fill_fragmentation() {
        let fee_bps = 1_000;
        let quantity = 100;
        let yes_escrow = required_escrow_atoms(OrderSide::BuyYes, quantity, 50_000_000).unwrap();
        let no_escrow = required_escrow_atoms(OrderSide::BuyNo, quantity, 50_000_000).unwrap();
        let mut yes = MatchOrderState {
            side: OrderSide::BuyYes,
            seq: 1,
            limit_p_yes_e8: 50_000_000,
            qty_remaining_atoms: quantity,
            escrow_remaining_atoms: yes_escrow,
            fee_remaining_atoms: protocol_fee_ceil(yes_escrow, fee_bps).unwrap(),
            taker_cost_basis_atoms: 0,
            protocol_fee_paid_atoms: 0,
        };
        let mut no = MatchOrderState {
            side: OrderSide::BuyNo,
            seq: 2,
            limit_p_yes_e8: 50_000_000,
            qty_remaining_atoms: quantity,
            escrow_remaining_atoms: no_escrow,
            fee_remaining_atoms: protocol_fee_ceil(no_escrow, fee_bps).unwrap(),
            taker_cost_basis_atoms: 0,
            protocol_fee_paid_atoms: 0,
        };
        let mut total_fee = 0_u64;

        while no.qty_remaining_atoms > 0 {
            let (yes_after, no_after, settlement) =
                settle_crossing_orders(yes, no, fee_bps, 2).unwrap();
            yes = yes_after;
            no = no_after;
            total_fee = total_fee
                .checked_add(settlement.total_protocol_fee_atoms)
                .unwrap();
        }

        assert_eq!(no.taker_cost_basis_atoms, 50);
        assert_eq!(total_fee, protocol_fee_floor(50, fee_bps).unwrap());
        assert_eq!(no.protocol_fee_paid_atoms, total_fee);
    }

    #[test]
    fn pair_local_crossing_does_not_require_global_best_prices() {
        let yes = MatchOrderState {
            side: OrderSide::BuyYes,
            seq: 90,
            limit_p_yes_e8: 60_000_000,
            qty_remaining_atoms: 10,
            escrow_remaining_atoms: required_escrow_atoms(OrderSide::BuyYes, 10, 60_000_000)
                .unwrap(),
            fee_remaining_atoms: 0,
            taker_cost_basis_atoms: 0,
            protocol_fee_paid_atoms: 0,
        };
        let no = MatchOrderState {
            side: OrderSide::BuyNo,
            seq: 91,
            limit_p_yes_e8: 40_000_000,
            qty_remaining_atoms: 10,
            escrow_remaining_atoms: required_escrow_atoms(OrderSide::BuyNo, 10, 40_000_000)
                .unwrap(),
            fee_remaining_atoms: 0,
            taker_cost_basis_atoms: 0,
            protocol_fee_paid_atoms: 0,
        };

        let (_, _, settlement) = settle_crossing_orders(yes, no, 0, 10).unwrap();
        assert_eq!(settlement.qty_atoms, 10);
        assert_eq!(settlement.maker_seq, 90);
        assert_eq!(settlement.p_exec_e8, 60_000_000);
    }
}
