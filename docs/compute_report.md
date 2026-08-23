# Anchor Program Compute Report

Date: 2026-08-15

Program: `913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A`

## Method

The before and after binaries were built with `anchor build` and loaded into fresh
Agave `solana-test-validator` 3.0.15 ledgers. The same 10 active TypeScript
integration scenarios exercised every public instruction. The collector reads
successful confirmed transactions through RPC and attributes the outer program's
`Program ... consumed N ... compute units` log to its Anchor instruction.

Values below are medians of successful samples from the complete suite. Instructions
with one successful invocation therefore show that single measurement. PDA creation
and conditional account-close paths can vary between transactions; the collector
also reports minimum, maximum, and all samples when run directly.

Solana currently gives a non-builtin instruction a default 200,000 CU limit and
recommends measuring transactions before selecting a tighter limit. Priority fees
are based on the requested limit rather than actual use. See the official
[compute-budget documentation](https://solana.com/docs/core/fees/compute-budget).

## Results

| Instruction | Before CU | After CU | CU saved | Savings |
|---|---:|---:|---:|---:|
| `cancel_order` | 11,748 | 11,748 | 0 | 0.0% |
| `claim_refunds` | 16,300 | 15,012 | 1,288 | 7.9% |
| `initialize_market_v2` | 42,995 | 42,782 | 213 | 0.5% |
| `initialize_notary_config` | 12,825 | 9,765 | 3,060 | 23.9% |
| `lock_market` | 5,177 | 5,167 | 10 | 0.2% |
| `match_orders` | 22,674 | 20,763 | 1,911 | 8.4% |
| `place_order` | 29,016 | 28,792 | 224 | 0.8% |
| `redeem` | 17,831 | 16,329 | 1,502 | 8.4% |
| `resolve_market_threshold` | 9,815 | 9,815 | 0 | 0.0% |
| `set_market_fee_config` | 5,148 | 5,137 | 11 | 0.2% |
| `sync_market_status` | 4,819 | 4,819 | 0 | 0.0% |
| `transfer_market_authority` | 5,072 | 5,063 | 9 | 0.2% |
| `unlock_market` | 5,179 | 5,169 | 10 | 0.2% |
| `update_market_schedule` | 5,239 | 5,231 | 8 | 0.2% |
| `update_notary_config` | 6,188 | 6,101 | 87 | 1.4% |
| `withdraw_protocol_fees` | 13,629 | 13,627 | 2 | <0.1% |
| **Sum of instruction medians** | **213,655** | **205,320** | **8,335** | **3.9%** |

The summed row is an equal-weight comparison of instruction medians, not the cost
of a single transaction or a production workload forecast.

## Changes

- `claim_refunds` no longer marks the read-only market account writable, avoiding
  unnecessary account serialization and reducing write-lock pressure.
- `match_orders` no longer marks the validation-only quote vault writable. It also
  moves order-to-market validation into the account contract and avoids repeated
  key reads in the handler.
- Probability, fee, and invalid-payout calculations use bounded `u64` quotient and
  remainder arithmetic instead of `u128` division; the integration benchmark
  captures the resulting savings on trading and invalid-redemption paths.
- Notary initialization and rotation update only the active key prefix and the
  previously populated tail. They no longer construct and copy a fresh 32-key,
  1,024-byte array for common one- and two-key configurations.
- Authority checks are performed once by Anchor `has_one` constraints; duplicate
  handler checks were removed while retaining the same custom errors.
- Newly initialized accounts rely on Solana's zeroed account data for fields whose
  protocol value is zero, avoiding redundant assignments.
- Frequently reused market, owner, and order keys are read once on the trading hot
  paths.

## Deliberately retained costs

- The Ed25519 scan loop and 235-byte resolution-message vector were benchmarked in
  alternative fixed-buffer forms. Both increased CU consumption, so the original
  pre-sized vector and bounded reverse scan were restored. Resolution finishes at
  the same 9,815 CU median.
- No account uses `realloc`, so there was no account reallocation cost to remove.
- No unnecessary `.clone()` remained in the instruction implementation.
- Typed Anchor and SPL Token account deserialization remains in place where it
  enforces mint, owner, PDA, or authority security invariants.
- Each token-moving instruction already performs the minimum one SPL Token transfer
  CPI. Combining or removing those CPIs would change custody behavior. Solana's
  compute-budget reference accounts for a fixed CPI invocation cost, so avoiding
  additional CPIs remains important.

## Reproduction

1. Build and start a fresh validator with the desired program binary.
2. Run `npm test`.
3. Run:

   ```text
   node scripts/collect_compute_units.mjs 913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A
   ```

The collector intentionally excludes failed transactions and reports program-level
CU, including CPIs charged to the Prophet invocation, rather than total transaction
CU from unrelated Ed25519 or setup instructions.
