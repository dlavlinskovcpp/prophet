# Anchor 1.0 compatibility report

## Status

`ANCHOR 1.0 MIGRATION BLOCKED`

The Rust host tests and SBF compilation succeed, and the static protocol ABI is unchanged. Final approval is blocked because Agave 3.1.10 was not available locally and its automatic download could not complete at the available network rate. Consequently the Anchor-generated IDL, deployment, and validator-backed suites have not been completed.

## Toolchain observed

| Component | Result |
| --- | --- |
| Host Rust | 1.89.0 installed and workspace-pinned |
| Anchor crates | `anchor-lang = 1.0.1`, `anchor-spl = 1.0.1` |
| Anchor CLI | Official 1.0.1 binary installed; SHA-256 `7b93381891b35e8a215515d564e9f032e93981b4c02d8b0715b6bf559065f543`. A pre-existing standalone 0.30.1 binary still shadows AVM on the local `PATH`; CI installs 1.0.1 directly. |
| Requested Agave CLI | 3.1.10 pinned in `Anchor.toml` and CI; local installation incomplete |
| SBF build used | `cargo-build-sbf 4.0.0`, platform-tools v1.53, Rust 1.89.0 |
| Node / Yarn | 20.19.6 / 1.22.22 |
| TypeScript | 5.3.3, the minimum required by the Anchor 1.0 client dependency graph |

## ABI comparison

The pre-migration reference is `anchor_0_30_protocol_snapshot.json`, captured from commit `544181ee04cd40d1fdf7fbfb837b6b306b04ca2b` before migration edits.

| Surface | Result | Classification |
| --- | --- | --- |
| Program ID | Unchanged: `913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A` | COMPATIBLE API DIFFERENCE |
| Instruction names | All 17 wrappers unchanged | COMPATIBLE API DIFFERENCE |
| Instruction discriminators | Names and default discriminator derivation unchanged | COMPATIBLE API DIFFERENCE |
| Instruction arguments | Types and ordering unchanged | COMPATIBLE API DIFFERENCE |
| Instruction accounts | Names and ordering unchanged | COMPATIBLE API DIFFERENCE |
| PDA seeds | Market, notary config, order, and position expressions unchanged | COMPATIBLE API DIFFERENCE |
| Account discriminators | Account names and default discriminator derivation unchanged | COMPATIBLE API DIFFERENCE |
| Account fields | All field names, types, and ordering unchanged | COMPATIBLE API DIFFERENCE |
| Account allocations | Market 392, NotaryConfig 1080, Order 136, Position 136 bytes including discriminator; unchanged | COMPATIBLE API DIFFERENCE |
| Events | Names and field definitions unchanged | COMPATIBLE API DIFFERENCE |
| Errors | All 51 variants retain their order and codes 6000–6050 | COMPATIBLE API DIFFERENCE |
| CPI construction | Program `AccountInfo` replaced by `Token::id()` as required by Anchor 1.0 | EXPECTED TOOLING DIFFERENCE |
| Raw unchecked accounts | `AccountInfo` replaced by `UncheckedAccount` without changing account metas or constraints | EXPECTED TOOLING DIFFERENCE |
| Instructions sysvar APIs | Imports moved to modular Solana 3 crates; address and parsing behavior retained | EXPECTED TOOLING DIFFERENCE |
| Layout unit test | `try_to_vec` replaced by `borsh::to_vec`; assertions and serialized objects unchanged | EXPECTED TOOLING DIFFERENCE |

No `PROTOCOL BREAKING CHANGE` was identified by the source-level and serialization checks completed so far.

## IDL comparison

The semantic Anchor 0.30 IDL is recorded in the snapshot. A new Anchor 1.0 IDL could not be generated because `anchor build` attempted to install the missing pinned Agave 3.1.10 distribution and that download did not complete.

This gate remains incomplete. Purely representational IDL changes must be ignored, while instruction names, arguments, account ordering, user-defined types, events, and errors must match the snapshot before approval.

## Verification results

| Check | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo test --workspace` | PASS — 11 passed, 0 failed |
| Direct SBF compilation | PASS with platform-tools v1.53 |
| `anchor build` with CLI 1.0.1 and Agave 3.1.10 | BLOCKED — pinned Agave download incomplete |
| TypeScript dependency syntax | PASS after pinning TypeScript 5.3.3 |
| Generated TypeScript program types | BLOCKED — Anchor IDL/types not generated |
| zkTLS security guardrail audit | PASS |
| Python SDK, keeper, and attester unit suites | BLOCKED locally — Poetry is not installed |
| Manual deployment | BLOCKED — Agave 3.1.10 validator unavailable |
| Anchor integration tests | BLOCKED — deployment unavailable |
| Validator-backed Python/E2E/smoke suites | BLOCKED — deployment unavailable |

The usual Anchor/Solana macro `unexpected_cfgs` warnings remain. They were not broadly suppressed.

## Required completion steps

1. Install the already-pinned Agave 3.1.10 distribution on a network-capable runner.
2. Verify `anchor-cli 1.0.1`, `solana-cli 3.1.10`, `solana-test-validator 3.1.10`, and platform-tools v1.53.
3. Run `anchor build` and compare `target/idl/prophet.json` and generated types with the snapshot.
4. Start `solana-test-validator` explicitly, deploy, and verify `solana program show 913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A`.
5. Run the complete integration, SDK, keeper, attester, E2E, smoke, release-bundle, security-bundle, and named security-regression suites.
6. Change this status to `ANCHOR 1.0 MIGRATION PASSED` only after every remaining gate succeeds.
