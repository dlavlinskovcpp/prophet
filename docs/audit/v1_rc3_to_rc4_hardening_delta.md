# v1 RC3 to RC4 hardening delta

This document records the RC4 remediation delta without changing protocol/on-chain semantics.

## Completed RC4 batches

- Batch 1: keeper and manifest hygiene.
- Batch 2: Poetry lock reproducibility.
- Batch 2B: portable Solana dependency contract (`solana==0.33.0`, `solders==0.21.0`).
- Batch 3: production container build.
- Batch 4: bounded resource hardening.
- Batch 5: CI/release/preflight gates in this candidate.

## Finding closure matrix

| Finding class | Original defect | Remediation / affected components | Verification and compatibility | Residual classification |
|---|---|---|---|---|
| Keeper selection and identity | A self-owned top-of-book pair could starve a valid crossed pair; runtime configuration could rely on an historical program-ID default. | The matching engine searches deterministic distinct-owner candidates; `PROPHET_PROGRAM_ID` is required and canonically parsed. | Full keeper suite covers valid-pair selection, only-self-match `None`, ordering, and missing/invalid program ID. No protocol instruction changed. | **CLOSED** |
| Release/manifest hygiene | Broad JSON ignore behavior and release workflows risked treating local key material or rewritten configuration as release evidence. | Secret/keypair scanning and bundle recursion checks; source configuration validation separated from ephemeral CI copies. | P-07 tests, checked-in config negative tests, and release-bundle inspection. No deployed identity or key is created by RC4. | **CLOSED** |
| Poetry dependency reproducibility | Production-sensitive Python environments could be incomplete or resolve differently from a committed lock. | Committed locks for SDK, oracle-attester, and keeper are checked and installed with Poetry 1.8.5; exact Solana pair is pinned. | Locked installs plus `solana==0.33.0` / `solders==0.21.0` runtime assertions. Canonical message and signature code are unchanged. | **CLOSED** |
| Portable Solana runtime | Solders 0.20.0 lacked required RPC modules on Linux ARM64. | Exact `solana==0.33.0`, `solders==0.21.0` lock contract. | Recorded macOS, Linux AMD64, and Linux ARM64 import evidence in `rc4_portable_solana_dependency_contract.md`. | **CLOSED** |
| Production Docker packaging | Root-context path dependencies and runtime imports were not mandatory build evidence; test/build packages could leak into runtime. | Oracle and keeper Dockerfiles use repository-root build context and locked main dependencies; CI builds/import-tests both. | Runtime imports assert Solders/Solana modules and reject pytest, pytest-asyncio, Poetry, and compiler tools. No service semantics changed. | **CLOSED** |
| External input/resource controls | Resolver body reads, HTTP proof/registry responses, audit durability, identity cardinality, and legacy zkTLS status parsing lacked the RC4 controls. | Streaming byte bounds, decoded proof limits, persistent registry audit mount, bounded registry limiter, safe XFF default, strict JSON boolean parsing. | Batch-4 tests plus full oracle non-E2E suite; see `rc4_batch4_bounded_resources.md`. | **CLOSED** for operated production services; retained legacy/test-only attester paths are not deployed as production settlement services. |
| Release/CI policy | CI could use an ephemeral rewritten environment as apparent source-config validation; production image, quality, SDK, and supply-chain checks were incomplete. | Separate untouched-config gate, production-image build/import gate, full SDK tests, Rust fmt/locked tests/Clippy, secret gate, audit/SBOM gates. | CI workflow inspection and local equivalents. Audit exceptions are explicit, narrow, and expiring. | **CLOSED** |

No RC4 remediation changes `PROPHET_RESOLVE_V2`, Resolver V2 canonical serialization
or vectors, signed-oracle framing, Ed25519 instruction layout, market layout,
NotaryConfig snapshots, instruction discriminators, or PDA derivations.

## Batch 5 security boundaries

- **CLOSED — checked-in config validation:** source files are validated before any ephemeral CI rewrite. Public-devnet uses the intended `3AUW4e…` identity; mainnet remains a future, unapproved identity and cannot deploy while authorization is false.
- **CLOSED — production packaging:** the actual oracle and keeper Dockerfiles are built from repository-root context; oracle runtime imports and `solana==0.33.0` / `solders==0.21.0` are asserted; pytest/pytest-asyncio/Poetry and package-management tooling are absent from runtime images. The Python base is pinned by digest; the prior mutable final-stage `apt-get upgrade` was removed.
- **CLOSED — lock authority:** all three Poetry projects run `poetry check --lock`, install from committed lockfiles, and CI rejects lock/pyproject mutation. Normal CI never runs `poetry lock`.
- **CLOSED — SDK policy:** the SDK runs the complete `tests` directory rather than a hand-selected pair.
- **CLOSED — Rust quality:** fmt, locked workspace tests, and strict Clippy are mandatory.
- **CLOSED — P-07 regression gate:** release-bundle secret tests remain mandatory and a tracked release/deployment secret scanner adds `.env`, wallet/keypair, Solana key-array, and credential-literal checks without touching real operator directories.
- **CLOSED — minimum supply chain:** pinned cargo-audit, pip-audit, Yarn audit, final-runtime Trivy scanning, and SPDX JSON SBOM generation are CI gates. The image gate scans both the merged final filesystem and the Syft-generated runtime SBOM, avoiding deleted layer-history metadata; each remaining Debian HIGH/CRITICAL advisory has an exact, expiring, machine-validated disposition.
- **CLOSED — local parity:** obsolete `solanalabs/solana:v1.17.0` local validator semantics are removed; native Agave/Solana 3.1.10 is authoritative.
- **DEFERRED HARDENING — Python repo-wide lint/format migration:** not introduced because it would require unrelated cleanup.
- **DEFERRED HARDENING — long-running fuzzing:** no supported fuzz-target corpus is present; deterministic 100k state-machine invariant remains mandatory in release/freeze CI.
- **NEEDS REAL INFRA / NEEDS LIVE VALIDATION:** real public-devnet secrets, independent services, funding, alert delivery, lifecycle/recovery drills, soak, and external audit remain outside code readiness.

**RC4 is not externally audited.**

**RC4 does not authorize mainnet.**
