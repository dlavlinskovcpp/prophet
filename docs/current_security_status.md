# Current Prophet security status

This file records the current release-line truth only. Historical audit
records under `docs/audit/` are immutable evidence and are not rewritten.

- The current release candidate is `v1.0.0-rc4.7` on the `initial-project`
  release branch; RC4.7 durability, supply-chain, and consensus-edge
  hardening is closed.
- Production uses fixed-role signer services; generic and role-selectable
  production signer paths remain unreachable.
- Production processes do not possess both A+B signer credentials.
- SQLite journals require WAL, synchronous FULL, foreign keys, bounded busy
  timeout, startup read-back, and fail-closed initialization.
- Settlement proof and public-input hashes must be non-zero.
- The protocol accepts legacy SPL Token only; Token-2022 is unsupported and
  must be rejected by operated tooling.
- Invalid-market redemption retains the one-atom carry for V1: aggregate
  collateral is conserved, while the recipient of the final atom is
  redemption-order dependent. Operated quote assets must therefore have a
  bounded one-atom value; the carry is not authority- or relayer-selectable.
- Remaining dependency exceptions are recorded in the current Rust, image,
  and Yarn exception inventories and require explicit owner review. An
  external security audit is required before mainnet.
- Public devnet is PAUSED. Program deployment is not authorized. Mainnet is
  BLOCKED. No deployment is authorized by this status file.
