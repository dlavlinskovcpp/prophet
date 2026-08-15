//! Phase 2 invariant tests.
//!
//! These are deliberately model-based tests over the same pure settlement and
//! payout functions called by instructions. They exercise long adversarial
//! action sequences without relying on a validator or on line-coverage goals.

use crate::{
    math::{
        mul_div_ceil, mul_div_floor, protocol_fee_ceil, protocol_fee_floor, redemption_payout,
        required_escrow_atoms, settle_crossing_orders, MatchOrderState,
    },
    state::{MarketOutcome, OrderSide, MAX_PROTOCOL_FEE_BPS, PROBABILITY_SCALE},
};

const SEQUENCE_COUNT: u64 = 4_096;
const STEPS_PER_SEQUENCE: usize = 96;
const SEED_MIX: u64 = 0x8f6a_6c29_7d31_4be5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelStatus {
    Open,
    Locked,
    Resolved,
}

#[derive(Clone, Debug)]
struct ModelPosition {
    yes: u64,
    no: u64,
    pending_refunds: u64,
    redeemed: bool,
    paid_out: u64,
}

#[derive(Clone, Debug)]
struct ModelOrder {
    original_qty: u64,
    position: usize,
    active: bool,
    state: MatchOrderState,
}

#[derive(Clone, Debug)]
struct ModelMarket {
    status: ModelStatus,
    outcome: MarketOutcome,
    invalid_remainder: u8,
    fee_bps: u16,
    positions: Vec<ModelPosition>,
    orders: Vec<ModelOrder>,
    deposits: u128,
    refunds_paid: u128,
    redemptions_paid: u128,
    fees_paid: u128,
    accrued_fees: u64,
}

impl ModelMarket {
    fn new(fee_bps: u16) -> Self {
        Self {
            status: ModelStatus::Open,
            outcome: MarketOutcome::Undecided,
            invalid_remainder: 0,
            fee_bps,
            positions: (0..4)
                .map(|_| ModelPosition {
                    yes: 0,
                    no: 0,
                    pending_refunds: 0,
                    redeemed: false,
                    paid_out: 0,
                })
                .collect(),
            orders: Vec::new(),
            deposits: 0,
            refunds_paid: 0,
            redemptions_paid: 0,
            fees_paid: 0,
            accrued_fees: 0,
        }
    }

    fn place(&mut self, position: usize, side: OrderSide, limit: u32, qty: u64) -> bool {
        if self.status != ModelStatus::Open || limit > PROBABILITY_SCALE || qty == 0 {
            return false;
        }
        let escrow = required_escrow_atoms(side, qty, limit).expect("valid model escrow");
        let fee = protocol_fee_ceil(escrow, self.fee_bps).expect("valid model fee reserve");
        self.deposits += u128::from(escrow) + u128::from(fee);
        self.orders.push(ModelOrder {
            original_qty: qty,
            position,
            active: true,
            state: MatchOrderState {
                side,
                seq: self.orders.len() as u64,
                limit_p_yes_e8: limit,
                qty_remaining_atoms: qty,
                escrow_remaining_atoms: escrow,
                fee_remaining_atoms: fee,
                taker_cost_basis_atoms: 0,
                protocol_fee_paid_atoms: 0,
            },
        });
        true
    }

    fn match_orders(&mut self, yes_index: usize, no_index: usize, max_qty: u64) -> bool {
        // The on-chain handler rejects matching in every terminal state. Keep
        // this guard ahead of order selection so a failed terminal operation is
        // provably a no-op in the model.
        if self.status != ModelStatus::Open || yes_index == no_index || max_qty == 0 {
            return false;
        }
        let Some(yes) = self.orders.get(yes_index) else {
            return false;
        };
        let Some(no) = self.orders.get(no_index) else {
            return false;
        };
        if !yes.active
            || !no.active
            || yes.position == no.position
            || yes.state.side != OrderSide::BuyYes
            || no.state.side != OrderSide::BuyNo
        {
            return false;
        }

        let yes_before = yes.state;
        let no_before = no.state;
        let Ok((yes_after, no_after, settlement)) =
            settle_crossing_orders(yes_before, no_before, self.fee_bps, max_qty)
        else {
            return false;
        };

        let yes_position = self.orders[yes_index].position;
        let no_position = self.orders[no_index].position;
        self.orders[yes_index].state = yes_after;
        self.orders[no_index].state = no_after;
        self.positions[yes_position].pending_refunds +=
            settlement.refund_yes_atoms + settlement.fee_refund_yes_atoms;
        self.positions[no_position].pending_refunds +=
            settlement.refund_no_atoms + settlement.fee_refund_no_atoms;
        self.positions[yes_position].yes += settlement.qty_atoms;
        self.positions[no_position].no += settlement.qty_atoms;
        self.accrued_fees += settlement.total_protocol_fee_atoms;
        if yes_after.qty_remaining_atoms == 0 {
            self.orders[yes_index].active = false;
        }
        if no_after.qty_remaining_atoms == 0 {
            self.orders[no_index].active = false;
        }
        true
    }

    fn cancel(&mut self, index: usize) -> bool {
        let Some(order) = self.orders.get(index) else {
            return false;
        };
        if !order.active {
            return false;
        }
        let position = order.position;
        let refund = order.state.escrow_remaining_atoms + order.state.fee_remaining_atoms;
        self.positions[position].pending_refunds += refund;
        self.orders[index].active = false;
        self.orders[index].state.qty_remaining_atoms = 0;
        self.orders[index].state.escrow_remaining_atoms = 0;
        self.orders[index].state.fee_remaining_atoms = 0;
        true
    }

    fn lock(&mut self) -> bool {
        if self.status == ModelStatus::Resolved {
            return false;
        }
        self.status = ModelStatus::Locked;
        true
    }

    fn unlock(&mut self) -> bool {
        if self.status != ModelStatus::Locked {
            return false;
        }
        self.status = ModelStatus::Open;
        true
    }

    fn resolve(&mut self, outcome: MarketOutcome) -> bool {
        if self.status == ModelStatus::Resolved || outcome == MarketOutcome::Undecided {
            return false;
        }
        self.status = ModelStatus::Resolved;
        self.outcome = outcome;
        true
    }

    fn redeem(&mut self, position: usize) -> bool {
        if self.status != ModelStatus::Resolved || position >= self.positions.len() {
            return false;
        }
        let entry = &mut self.positions[position];
        let (payout, remainder) =
            redemption_payout(self.outcome, entry.yes, entry.no, self.invalid_remainder)
                .expect("model remainder stays bounded");
        // A second redemption is permitted by the instruction but must burn no
        // additional shares and transfer no additional collateral.
        if entry.redeemed {
            assert_eq!(payout, 0, "double redemption paid collateral");
        }
        entry.yes = 0;
        entry.no = 0;
        entry.redeemed = true;
        entry.paid_out += payout;
        self.invalid_remainder = remainder;
        self.redemptions_paid += u128::from(payout);
        true
    }

    fn refund(&mut self, position: usize, requested: u64) -> bool {
        let Some(entry) = self.positions.get_mut(position) else {
            return false;
        };
        let paid = requested.min(entry.pending_refunds);
        if paid == 0 {
            return false;
        }
        entry.pending_refunds -= paid;
        self.refunds_paid += u128::from(paid);
        true
    }

    fn withdraw_fees(&mut self, requested: u64) -> bool {
        let paid = requested.min(self.accrued_fees);
        if paid == 0 {
            return false;
        }
        self.accrued_fees -= paid;
        self.fees_paid += u128::from(paid);
        true
    }

    fn assert_invariants(&self) {
        let mut active_escrow = 0_u128;
        let mut active_fee_reserves = 0_u128;
        for order in &self.orders {
            assert!(
                order.state.qty_remaining_atoms <= order.original_qty,
                "filled quantity exceeds original quantity"
            );
            if order.active {
                assert!(
                    order.state.qty_remaining_atoms > 0,
                    "zero-quantity order remained active"
                );
                active_escrow += u128::from(order.state.escrow_remaining_atoms);
                active_fee_reserves += u128::from(order.state.fee_remaining_atoms);
            } else {
                assert_eq!(
                    order.state.qty_remaining_atoms, 0,
                    "closed order has remaining quantity"
                );
                assert_eq!(
                    order.state.escrow_remaining_atoms, 0,
                    "closed order retains escrow"
                );
                assert_eq!(
                    order.state.fee_remaining_atoms, 0,
                    "closed order retains fee reserve"
                );
            }
        }

        let yes: u128 = self.positions.iter().map(|p| u128::from(p.yes)).sum();
        let no: u128 = self.positions.iter().map(|p| u128::from(p.no)).sum();
        let settlement_liability = match self.status {
            ModelStatus::Open | ModelStatus::Locked => {
                assert_eq!(yes, no, "YES and NO claims must remain mirrored");
                yes
            }
            ModelStatus::Resolved => match self.outcome {
                MarketOutcome::Yes => yes,
                MarketOutcome::No => no,
                // The carry is part of the remaining claim numerator. It
                // pairs an earlier odd half with the next redemption, so this
                // expression remains integral for a conserved two-sided book.
                MarketOutcome::Invalid => (yes + no + u128::from(self.invalid_remainder)) / 2,
                MarketOutcome::Undecided => 0,
            },
        };
        let pending_refunds: u128 = self
            .positions
            .iter()
            .map(|p| u128::from(p.pending_refunds))
            .sum();
        let actual_vault =
            self.deposits - self.refunds_paid - self.redemptions_paid - self.fees_paid;
        let required_vault = active_escrow
            + active_fee_reserves
            + pending_refunds
            + settlement_liability
            + u128::from(self.accrued_fees);
        assert_eq!(
            actual_vault, required_vault,
            "collateral conservation failed"
        );

        if self.status == ModelStatus::Resolved {
            // A terminal market may still cancel orders, refund, redeem, and
            // withdraw accrued fees, but it may never match or place again.
            for order in &self.orders {
                assert!(
                    order.state.qty_remaining_atoms <= order.original_qty,
                    "terminal market mutated an order beyond its original quantity"
                );
            }
        }
    }
}

#[derive(Clone, Copy)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn range(&mut self, upper_exclusive: usize) -> usize {
        (self.next() % upper_exclusive as u64) as usize
    }
}

fn run_sequence(seed: u64) {
    let mut rng = SplitMix64(seed);
    let mut market = ModelMarket::new((rng.next() % (u64::from(MAX_PROTOCOL_FEE_BPS) + 1)) as u16);

    for step in 0..STEPS_PER_SEQUENCE {
        match rng.range(10) {
            0 | 1 => {
                let side = if rng.next() & 1 == 0 {
                    OrderSide::BuyYes
                } else {
                    OrderSide::BuyNo
                };
                // Prices deliberately include extremal and odd values to force
                // both escrow and settlement rounding paths.
                let limit = match rng.range(6) {
                    0 => 0,
                    1 => 1,
                    2 => PROBABILITY_SCALE - 1,
                    3 => PROBABILITY_SCALE,
                    _ => (rng.next() % (u64::from(PROBABILITY_SCALE) + 1)) as u32,
                };
                let _ = market.place(
                    rng.range(market.positions.len()),
                    side,
                    limit,
                    1 + rng.next() % 257,
                );
            }
            2 | 3 => {
                let _ = market.match_orders(
                    rng.range(market.orders.len().max(1)),
                    rng.range(market.orders.len().max(1)),
                    1 + rng.next() % 128,
                );
            }
            4 => {
                let _ = market.cancel(rng.range(market.orders.len().max(1)));
            }
            5 => {
                let _ = market.lock();
            }
            6 => {
                let _ = market.unlock();
            }
            7 => {
                let outcome = match rng.range(3) {
                    0 => MarketOutcome::Yes,
                    1 => MarketOutcome::No,
                    _ => MarketOutcome::Invalid,
                };
                let _ = market.resolve(outcome);
            }
            8 => {
                let _ = market.redeem(rng.range(market.positions.len()));
            }
            _ => {
                if rng.next() & 1 == 0 {
                    let _ =
                        market.refund(rng.range(market.positions.len()), 1 + rng.next() % 1_024);
                } else {
                    let _ = market.withdraw_fees(1 + rng.next() % 1_024);
                }
            }
        }
        market.assert_invariants();
        let _ = step;
    }
}

#[test]
fn state_machine_preserves_economic_invariants_for_thousands_of_seeds() {
    if let Ok(seed) = std::env::var("PROPHET_INVARIANT_SEED") {
        let seed = u64::from_str_radix(
            seed.trim_start_matches("0x"),
            if seed.starts_with("0x") { 16 } else { 10 },
        )
        .expect("PROPHET_INVARIANT_SEED must be a u64 decimal or 0x hexadecimal value");
        run_sequence(seed);
        return;
    }

    for offset in 0..SEQUENCE_COUNT {
        let seed = SEED_MIX.wrapping_add(offset.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        std::panic::catch_unwind(|| run_sequence(seed)).unwrap_or_else(|failure| {
            panic!(
                "state-machine invariant failed for reproducible seed 0x{seed:016x}; rerun with PROPHET_INVARIANT_SEED=0x{seed:016x}. {failure:?}"
            )
        });
    }
}

#[test]
fn regression_invalid_rounding_carry_conserves_every_atom_across_redemption_order() {
    // Regression for the historical invalid-market rounding loss. Different
    // redemption order must still distribute exactly the matched collateral.
    for seed in 0..1_024_u64 {
        let mut rng = SplitMix64(SEED_MIX ^ seed);
        let mut carry = 0_u8;
        let mut total_claims = 0_u128;
        let mut total_paid = 0_u128;
        for _ in 0..32 {
            let yes = rng.next() % 10_000;
            let no = rng.next() % 10_000;
            total_claims += u128::from(yes + no);
            let (payout, next) = redemption_payout(MarketOutcome::Invalid, yes, no, carry).unwrap();
            total_paid += u128::from(payout);
            carry = next;
        }
        // Pair the final odd atom with a final opposite share. The carry must
        // clear and exactly half the aggregate two-sided claims must be paid.
        if carry == 1 {
            let (payout, next) = redemption_payout(MarketOutcome::Invalid, 1, 0, carry).unwrap();
            total_claims += 1;
            total_paid += u128::from(payout);
            carry = next;
        }
        assert_eq!(carry, 0, "seed {seed:#x}");
        assert_eq!(total_paid * 2, total_claims, "seed {seed:#x}");
    }
}

#[test]
fn property_fee_is_independent_of_fragmentation_for_random_cost_partitions() {
    for seed in 0..4_096_u64 {
        let mut rng = SplitMix64(seed ^ SEED_MIX);
        let fee_bps = (rng.next() % (u64::from(MAX_PROTOCOL_FEE_BPS) + 1)) as u16;
        let total_cost = rng.next() % 1_000_000_000;
        let mut remaining = total_cost;
        let mut cumulative_cost = 0_u64;
        let mut cumulative_fee = 0_u64;
        while remaining > 0 {
            let fill = 1 + rng.next() % remaining.min(10_000);
            remaining -= fill;
            let prior_due = protocol_fee_floor(cumulative_cost, fee_bps).unwrap();
            cumulative_cost += fill;
            let next_due = protocol_fee_floor(cumulative_cost, fee_bps).unwrap();
            cumulative_fee += next_due - prior_due;
        }
        assert_eq!(
            cumulative_fee,
            protocol_fee_floor(total_cost, fee_bps).unwrap(),
            "seed {seed:#x}"
        );
    }
}

#[test]
fn property_matching_arithmetic_and_escrow_accounting_hold_for_random_crosses() {
    for seed in 0..4_096_u64 {
        let mut rng = SplitMix64(SEED_MIX.wrapping_add(seed));
        let fee_bps = (rng.next() % (u64::from(MAX_PROTOCOL_FEE_BPS) + 1)) as u16;
        let no_limit = (rng.next() % (u64::from(PROBABILITY_SCALE) + 1)) as u32;
        let yes_limit =
            no_limit + (rng.next() % u64::from(PROBABILITY_SCALE - no_limit + 1)) as u32;
        let yes_qty = 1 + rng.next() % 16_384;
        let no_qty = 1 + rng.next() % 16_384;
        let yes_escrow = required_escrow_atoms(OrderSide::BuyYes, yes_qty, yes_limit).unwrap();
        let no_escrow = required_escrow_atoms(OrderSide::BuyNo, no_qty, no_limit).unwrap();
        let yes = MatchOrderState {
            side: OrderSide::BuyYes,
            seq: if rng.next() & 1 == 0 { 1 } else { 2 },
            limit_p_yes_e8: yes_limit,
            qty_remaining_atoms: yes_qty,
            escrow_remaining_atoms: yes_escrow,
            fee_remaining_atoms: protocol_fee_ceil(yes_escrow, fee_bps).unwrap(),
            taker_cost_basis_atoms: 0,
            protocol_fee_paid_atoms: 0,
        };
        let no = MatchOrderState {
            side: OrderSide::BuyNo,
            seq: if yes.seq == 1 { 2 } else { 1 },
            limit_p_yes_e8: no_limit,
            qty_remaining_atoms: no_qty,
            escrow_remaining_atoms: no_escrow,
            fee_remaining_atoms: protocol_fee_ceil(no_escrow, fee_bps).unwrap(),
            taker_cost_basis_atoms: 0,
            protocol_fee_paid_atoms: 0,
        };
        let max_qty = 1 + rng.next() % yes_qty.min(no_qty);
        let before = u128::from(yes.escrow_remaining_atoms)
            + u128::from(yes.fee_remaining_atoms)
            + u128::from(no.escrow_remaining_atoms)
            + u128::from(no.fee_remaining_atoms);

        match settle_crossing_orders(yes, no, fee_bps, max_qty) {
            Ok((yes_after, no_after, settlement)) => {
                assert!(
                    settlement.qty_atoms > 0 && settlement.qty_atoms <= max_qty,
                    "seed {seed:#x}"
                );
                assert_eq!(
                    settlement.cost_yes_atoms + settlement.cost_no_atoms,
                    settlement.qty_atoms
                );
                assert_eq!(
                    yes_after.escrow_remaining_atoms,
                    required_escrow_atoms(
                        OrderSide::BuyYes,
                        yes_after.qty_remaining_atoms,
                        yes_limit
                    )
                    .unwrap(),
                    "seed {seed:#x}"
                );
                assert_eq!(
                    no_after.escrow_remaining_atoms,
                    required_escrow_atoms(OrderSide::BuyNo, no_after.qty_remaining_atoms, no_limit)
                        .unwrap(),
                    "seed {seed:#x}"
                );
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
                assert_eq!(before, after, "seed {seed:#x}");
                match settlement.taker_side {
                    OrderSide::BuyYes => assert_eq!(settlement.protocol_fee_no_atoms, 0),
                    OrderSide::BuyNo => assert_eq!(settlement.protocol_fee_yes_atoms, 0),
                }
            }
            // A fail-closed tiny rounded match is correct only when the two
            // releases cannot cover one complete matched claim.
            Err(_) => {
                let qty = max_qty.min(yes_qty.min(no_qty));
                let released_yes = yes_escrow
                    - required_escrow_atoms(OrderSide::BuyYes, yes_qty - qty, yes_limit).unwrap();
                let released_no = no_escrow
                    - required_escrow_atoms(OrderSide::BuyNo, no_qty - qty, no_limit).unwrap();
                assert!(released_yes + released_no < qty, "seed {seed:#x}");
            }
        }
    }
}

#[test]
fn property_overflow_boundaries_fail_closed_without_wrapping() {
    assert!(mul_div_floor(u64::MAX, 2, 1).is_err());
    assert!(mul_div_ceil(u64::MAX, 2, 1).is_err());
    assert!(mul_div_floor(1, 1, 0).is_err());
    assert!(mul_div_ceil(1, 1, 0).is_err());

    for price in [0, 1, PROBABILITY_SCALE - 1, PROBABILITY_SCALE] {
        let yes = required_escrow_atoms(OrderSide::BuyYes, u64::MAX, price).unwrap();
        let no = required_escrow_atoms(OrderSide::BuyNo, u64::MAX, price).unwrap();
        assert!(yes <= u64::MAX);
        assert!(no <= u64::MAX);
        assert!(protocol_fee_ceil(yes, MAX_PROTOCOL_FEE_BPS).is_ok());
        assert!(protocol_fee_ceil(no, MAX_PROTOCOL_FEE_BPS).is_ok());
    }

    assert!(redemption_payout(MarketOutcome::Invalid, u64::MAX, u64::MAX, 2).is_err());
    assert_eq!(
        redemption_payout(MarketOutcome::Invalid, u64::MAX, u64::MAX - 1, 1).unwrap(),
        (u64::MAX, 0)
    );
}
