# v1.0.0-rc4 scope and release-gate policy

RC4 preserves protocol/on-chain semantics, settlement architecture, `PROPHET_RESOLVE_V2`, NotaryConfig, and P-01..P-07. Batch 5 is CI/release/preflight hardening only.

## Batch 5 classifications

| Item | Classification | RC4 treatment |
|---|---|---|
| Checked-in environment validation | CLOSED | Untouched localnet/devnet/public-devnet/mainnet-beta files have a mandatory validator; CI ephemeral identity rewrites are explicitly separate. |
| Public-devnet source/Anchor/IDL/release identity | CLOSED | `3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE` is the match-source identity and is validated before ephemeral CI key sync. |
| Mainnet identity/authorization | CLOSED (code gate) | Mainnet remains `future-unapproved`, `deployment_authorized=false`, and may keep a future different ID; live deploy fails closed. |
| Production image packaging | CLOSED | CI builds both repository-root production images, import-tests the oracle runtime, verifies Solana dependency versions, and rejects dev tooling in runtime images. |
| Local validator parity | CLOSED | Misleading Solana v1.17 container dependency is removed; supported local workflow requires native Agave/Solana CLI 3.1.10. |
| Rust fmt/workspace tests/Clippy | CLOSED | Mandatory CI gates use Rust 1.89.0 and strict warnings. |
| SDK ordinary unit-test enumeration | CLOSED | SDK policy runs `pytest -q tests`; the localnet test remains self-gated by its runtime prerequisite. |
| Supply-chain minimum gates | CLOSED | Rust/Python/JS vulnerability checks plus production-image Trivy and SPDX SBOM are mandatory. |
| Python repository-wide formatter/linter | DEFERRED HARDENING | No unrelated mass rewrite was introduced. |
| Long-running fuzz lane | DEFERRED HARDENING | Deterministic 100k release/freeze invariant remains mandatory; no supported fuzz corpus exists in the repository. |
| Public-devnet secrets/services/funding | NEEDS REAL INFRA | No test secrets are injected to make runtime preflight green. |
| Public-devnet lifecycle/recovery/drills | NEEDS LIVE VALIDATION | Requires deployed services and operator evidence. |
| External security audit | NEEDS LIVE VALIDATION | RC4 is not externally audited. |

**RC4 is not externally audited.**

**RC4 does not authorize mainnet.**
