# v1.0.0-rc2 Release Checklist

Status: **RC2 code-freeze checklist**
Date: 2026-08-16
Reference freeze commit: `f5b85b4e43fa547d3fd12c1f58d69290dd96826a`

Do not use this checklist as deployment approval. Code, CI, infrastructure, live
devnet, audit and mainnet gates are intentionally separate.

## CODE GATES

- [x] Python 3.11 oracle-attester non-E2E matrix executed with repository dependencies.
  Result: **475 passed, 0 failed, 5 deselected**.
- [x] Real `solders==0.20.0` confirmed in the Poetry runtime environment.
- [x] `solana==0.32.0` confirmed.
- [x] Phase 6 runtime/security suites are included in the passing Python matrix:
  verifier services/runtime, dual verifier independence, adapter factory/runtime
  config, signed-oracle trust, zkTLS runtime, coordinator, Vault signer identity,
  single signer, strict 2/2, signing journal, restart/recovery, key rotation,
  AGREED→2/2, transaction construction, simulation, submission/reconciliation.
- [x] Explicit migration/restart/recovery matrix passes:
  **56 passed, 0 failed, 424 deselected**.
- [x] Python SDK test suite passes:
  **12 passed, 0 failed, 2 skipped**.
- [x] Local TypeScript/Anchor localnet suite executes real tests:
  **13 passing, 1 pending**. The pending case is the intentionally retired legacy
  single-oracle suite, not a failing active protocol test.
- [x] Rust workspace tests pass: Prophet **17/17**, Resolver V2 **4/4**.
- [x] Resolver V2 permanent vector/property tests pass.
- [x] Legacy resolution message compatibility test passes.
- [x] zkTLS guardrail audit passes.
- [x] `cargo fmt --all -- --check` passes.
- [x] `cargo clippy --workspace --all-targets` exits 0.
  Known Anchor/toolchain and pre-existing non-fatal warnings remain; RC2 does not
  refactor protocol code solely to silence those warnings.
- [x] `git diff --check` passes.
- [x] Secret scan over RC1 → working tree reviewed; no production credential,
  private key, seed phrase or fee-payer key material identified.
- [x] Test-only artifact scan reviewed; production paths reject deterministic/test
  zkTLS/Vault/RPC/trust material.
- [x] No production on-chain program/IDL/Resolver V2 core delta in the committed
  RC1 → RC2 reference diff.
- [x] Public-devnet env preflight fails closed on unresolved real infrastructure.
- [x] Public-devnet runtime YAML is syntactically valid and fails closed because
  the real production signed-oracle registry is not provisioned.
- [x] RC2 audit scope document prepared.
- [x] RC1 → RC2 security delta document prepared.
- [x] Public-devnet readiness matrix prepared.
- [x] Mainnet blocker list reviewed/extended for RC2.
- [x] Final code-freeze working-tree review completed before the freeze commit:
  `git status --short --untracked-files=all` was reviewed and `git diff --check`
  passed. The staged candidate contained only the expected release-hygiene/test
  changes plus the five RC2 audit-document changes.
- [x] Documentation application did not introduce executable/runtime changes.
  The release-hygiene code/test changes remain covered by the passing Python,
  Rust, migration/restart, SDK, zkTLS and TypeScript/Anchor local verification
  matrices above.


## Local code-freeze status

All locally required **CODE GATES** above are complete for the current working-tree
candidate. On that basis the local verdict is:

**RC2 CODE FREEZE READY**

The freeze candidate has also passed the GitHub CI gate recorded below.
Infrastructure, live-devnet, independent-audit and mainnet gates remain separate
and open.

## CI GATES

- [x] Final GitHub CI completed successfully on the RC2 freeze commit.
  - Commit: `f5b85b4e43fa547d3fd12c1f58d69290dd96826a`
  - GitHub Actions run: `31961480034`
  - Conclusion: **success**
- [x] Matching Keeper Tests — PASS.
- [x] Rust + zkTLS Audit — PASS.
- [x] Oracle Attester Tests — PASS.
- [x] Anchor TS Integration — PASS.
- [x] Ops Drill Checks — PASS.
- [x] SDK Python Tests — PASS.

## INFRA GATES

- [ ] Real public-devnet Vault provisioned.
- [ ] Vault TLS/auth/policy/audit configuration reviewed.
- [ ] Real signer A provisioned and public key/version pinned.
- [ ] Real signer B provisioned independently and public key/version pinned.
- [ ] Dedicated fee payer provisioned outside Git with restricted file/secret
  permissions and sufficient devnet funding.
- [ ] Verifier A production endpoint and credentials provisioned.
- [ ] Verifier B independently provisioned.
- [ ] Production signed-oracle registry provisioned and protected.
- [ ] Coordinator/signing/attempt SQLite paths mounted on durable storage.
- [ ] RPC provider/endpoint policy approved.
- [ ] Monitoring stack provisioned.
- [ ] Real alert receiver provisioned and delivery target owned.
- [ ] Backup destination, retention and restore procedure provisioned.
- [ ] Deployment runtime values replace `REPLACE_*` placeholders outside Git.
- [ ] Public-devnet preflight passes using only real infrastructure values.

## LIVE DEVNET GATES

- [ ] Prophet RC2 program/runtime deployed to public devnet under approved
  deployment procedure.
- [ ] Verifier A/B independence validated live.
- [ ] Coordinator durable operation validated live.
- [ ] Controlled live E2E settlement completed.
- [ ] Exact transaction simulation → submission → confirmation observed live.
- [ ] Restart/recovery drill completed using reopened real SQLite files.
- [ ] Uncertain Vault/recovery scenario rehearsed operationally.
- [ ] Signer key rotation drill completed with old intent versions remaining pinned.
- [ ] Ambiguous transaction submission/reconciliation drill completed with no
  blind rebroadcast.
- [ ] Backup/restore drill proves coordinator, signing and transaction-attempt
  security history survives restore.
- [ ] Real monitoring and alert delivery verified.
- [ ] Devnet soak period completed with incident/error review.

## AUDIT GATES

- [ ] RC2 audit scope frozen to exact commit/tree presented to auditors.
- [ ] Independent external audit completed.
- [ ] Audit includes verifier runtime, coordinator persistence/orchestration,
  Vault signing, anti-equivocation/recovery, key rotation, settlement
  construction/simulation/submission and relevant deployment trust boundaries.
- [ ] All security findings triaged.
- [ ] Required findings fixed.
- [ ] Fixes regression-tested.
- [ ] Auditor-required retest/review completed.
- [ ] Findings closure documented.
- [ ] No document describes RC2 runtime additions as already externally audited
  before those gates complete.

## MAINNET GATES

- [ ] Independent external audit and findings closure complete.
- [ ] Public-devnet deployment complete.
- [ ] Real Vault and signer provisioning complete.
- [ ] Real alert delivery proven.
- [ ] Live E2E settlement proven.
- [ ] Restart/recovery drill complete.
- [ ] Key rotation drill complete.
- [ ] Transaction reconciliation drill complete.
- [ ] Backup/restore drill complete.
- [ ] Soak period complete and reviewed.
- [ ] Mainnet-specific RPC, fee-payer, secret-management, monitoring and incident
  procedures reviewed.
- [ ] Separate explicit mainnet release authorization recorded.

## Code-freeze verdict rule

`RC2 CODE FREEZE READY` may be returned only when all **CODE GATES** required for
the candidate are complete, local protocol/runtime compatibility remains intact,
migrations/restart behavior is covered by the passing release matrix, the
secret/test-artifact review is clean, and the audit documentation is complete.

Open **INFRA**, **LIVE DEVNET**, **AUDIT** and **MAINNET** gates do not by themselves
block a code-freeze verdict.

The **CI GATES** remain explicit follow-on release gates and must be green before
the candidate is treated as a releasable/taggable RC2 artifact.
