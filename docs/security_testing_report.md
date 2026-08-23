# Phase 2 Security Testing Report

Date: 2026-08-15

## Objective and scope

This phase tests protocol invariants, not line coverage. It adds deterministic
property and state-machine tests around the pure arithmetic, matching, and
settlement functions used by the Anchor instruction handlers. It does not
change any instruction, account layout, validation rule, or economic feature.

The state machine uses four users, randomized order books, all allowed terminal
outcomes, and 4,096 deterministic seeds with 96 operations per seed (393,216
operations). It runs every assertion after every attempted operation. A failure
prints a hexadecimal seed and can be replayed exactly; the promotion procedure
is in `tests/security_regression_seeds.md`.

## Economic and state invariant catalog

| ID | Invariant | Enforcement / test evidence |
| --- | --- | --- |
| ECON-01 | Every order prefunds ceiling escrow plus its maximum fee reserve. | `place_order`, `required_escrow_atoms`; matching and escrow property tests. |
| ECON-02 | No asset is created or lost during a match: remaining escrow and reserves, refunds, accrued fee, and newly minted matched claims equal the pre-match deposit. | `settle_crossing_orders`; random matching/escrow property and state machine. |
| ECON-03 | Before resolution, aggregate YES claims equal aggregate NO claims; each successful match increases both by exactly the fill quantity. | `match_orders`; state machine after every operation. |
| ECON-04 | Execution costs partition a fill exactly: `cost_yes + cost_no = quantity`, and each cost is bounded by released collateral. | `settle_crossing_orders`; random matching property and fuzz target. |
| ECON-05 | An order never fills beyond its original quantity; a full fill or cancellation cannot retain escrow or fee reserve. | `match_orders`, `cancel_order`; state machine after every operation. |
| ECON-06 | Protocol fees are charged only to the taker and equal `floor(cumulative taker cost × bps / 10,000)`, independent of fill fragmentation. | `accrue_taker_fee`; fragmentation property and state machine. |
| ECON-07 | Fee withdrawal is bounded by accrued fees; refunds are bounded by pending refunds. | `withdraw_protocol_fees`, `claim_refunds`; state machine and `prophet_invariants.ts`. |
| ECON-08 | Vault collateral equals live order escrow + live fee reserves + pending refunds + remaining settlement liability + accrued fees. | State machine after every operation. |
| ECON-09 | YES and NO redeem exactly their winning claims; Invalid pays half of combined claims and carries an odd atom forward. | `redemption_payout`; invalid carry property, payout unit tests, and integration tests. |
| ECON-10 | No redemption transfers collateral twice; a second call has zero shares and zero payout. | `redeem`; state machine and `prophet_invariants.ts`. |
| ECON-11 | Arithmetic rejects division by zero and result overflow rather than wrapping; valid bounded quotient/remainder arithmetic agrees with `u128` reference math. | arithmetic unit/property tests and arithmetic fuzz target. |
| STATE-01 | Trading is permitted only while Open and inside the configured time window. | `require_market_open_for_trading`; lifecycle integration tests and state machine. |
| STATE-02 | Locked and Resolved are terminal for matching and new orders; resolved markets cannot be lock/unlocked/resolved again. | instruction guards; state machine terminal no-op checks. |
| STATE-03 | Cancellation, bounded refund, redemption, and bounded fee withdrawal preserve accounting after resolution. | instruction handlers; state machine after every operation. |
| STATE-04 | Open-order counters are consistent with live order accounts and cannot underflow. | placement/match/cancel handlers; `prophet_invariants.ts` and state machine. |
| STATE-05 | A resolved outcome is non-Undecided and is set once; payout liability changes only according to that outcome. | threshold resolution and payout tests. |
| STATE-06 | Market configuration, probability bounds, order sequence, account ownership/PDA binding, fee-recipient binding, and notary threshold/message validation fail closed. | existing Rust validation tests plus Anchor threshold/governance integration suites. |

## Added test assets

- `programs/prophet/src/security_tests.rs`
  - randomized fee fragmentation property (4,096 partitions)
  - randomized matching arithmetic and escrow accounting property (4,096 crosses)
  - invalid-market carry/rounding regression (1,024 generated claim sets)
  - fail-closed overflow boundary tests
  - 4,096 state-machine sequences spanning place, partial/full match, cancel,
    lock/unlock, YES/NO/INVALID resolution, redeem, refund, and fee withdrawal
- `fuzz/fuzz_targets/arithmetic.rs`: differential arithmetic fuzz target.
- `fuzz/fuzz_targets/settlement.rs`: valid crossing-order settlement conservation
  fuzz target.
- `tests/security_regression_seeds.md`: reproducible-state-machine seed corpus
  and promotion procedure.

The fuzz entrypoints are host-only behind the `fuzzing` Cargo feature; they add
no on-chain instruction or protocol behavior. Run them with the commands in
`fuzz/README.md`. `cargo-fuzz` preserves crashing inputs under `fuzz/artifacts/`;
those inputs must be minimized and added to the regression-seed document before
remediation.

## Previously fixed protocol vulnerability regressions

| Previously fixed class | Dedicated regression evidence |
| --- | --- |
| Settlement rounding could create an under-collateralized tiny match. | `property_matching_arithmetic_and_escrow_accounting_hold_for_random_crosses` verifies conservation or the fail-closed path. |
| Invalid outcome could strand an odd collateral atom. | `regression_invalid_rounding_carry_conserves_every_atom_across_redemption_order`; `math::payout` unit tests; threshold Invalid integration flow. |
| Per-fill fee rounding depended on fill fragmentation. | `property_fee_is_independent_of_fragmentation_for_random_cost_partitions`; `math::orders::taker_fee_is_invariant_to_fill_fragmentation`. |
| Refund or redemption could be invoked again. | `prophet_invariants.ts` bounded-claim/no-double-claim and no-double-redeem scenarios; state-machine double-redemption assertion. |
| Unsafe zero/inconsistent market limits could be configured. | `validation::market::rejects_zero_and_inconsistent_order_limits`. |
| Fee recipient could alias the market vault or fee policy could change after trading began. | `prophet_governance.ts` fee-config/recipient regression scenario. |
| Overflow or zero divisor could wrap settlement arithmetic. | `property_overflow_boundaries_fail_closed_without_wrapping`; arithmetic unit tests; arithmetic fuzz target. |
| Duplicate, stale, unauthorized, or over-window notary resolution evidence could resolve a market. | `prophet_threshold.ts` threshold, duplicate, wrong-message, stale-version, and scan-window regressions; notary validation unit tests. |

## Reproduction

```bash
cargo test -p prophet --lib
PROPHET_INVARIANT_SEED=0x8f6a6c297d314be5 \
  cargo test -p prophet --lib security_tests::state_machine_preserves_economic_invariants_for_thousands_of_seeds -- --exact
(cd fuzz && cargo fuzz run arithmetic -- -max_total_time=300)
(cd fuzz && cargo fuzz run settlement -- -max_total_time=300)
```

## Local verification evidence

Passed locally:

```text
cargo test -p prophet --lib                         # 16 passed
bash scripts/check_zktls.sh                          # passed
cargo check -p prophet                               # passed
cargo check --manifest-path fuzz/Cargo.toml ...      # passed
```

The full Anchor/Python GitHub Actions integration lane could not be reproduced
in this workspace: Anchor 1.0.1 correctly attempted to obtain the `3.1.10`
Agave release declared in `Anchor.toml`, but the local installer stalled without
installing that release. The locally present Agave release is `3.0.15` and must
not be substituted for the CI-pinned `3.1.10`. Separately, the local ignored
Oracle Attester Poetry lockfile does not match its tracked `pyproject.toml`;
regenerating it would be an unrelated dependency change and was intentionally
not done. CI's clean locked environment remains the authoritative full-lane
runner.

## Result

INVARIANT TESTING PASSED
