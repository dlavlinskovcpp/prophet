# RC4 supply-chain and dependency gate policy

Status: RC4 Batch 5 release policy.

## Mandatory automated gates

- Rust project builds/tests stay on Rust 1.89.0. `cargo audit` is pinned to 0.22.2 and audits the committed `Cargo.lock` against a separately fetched RustSec advisory database.
- Python environments are installed from each committed Poetry lock without running `poetry lock`. `pip-audit` is pinned to 2.10.1 and audits each installed locked environment.
- JavaScript dependencies use the committed Yarn lock and Yarn 1.22.22. Registry reachability is checked separately from `yarn audit` so network/tool failure is distinguishable from findings.
- Production oracle and keeper images are built from repository-root context. Trivy is pinned to 0.74.0. CI scans both the merged final runtime filesystem (Debian/OS packages) and a Syft-generated SPDX SBOM (application packages). This deliberately avoids treating deleted lower-layer metadata or external provenance as a live runtime dependency. The two reports are retained with the SBOM artifact.
- Syft is pinned to 1.50.0 and emits SPDX JSON SBOMs for both production images. CI writes metadata associating the SBOMs with commit SHA, image references, and the `ci-<sha>` release-candidate identifier.

No vulnerability gate uses a permanent blanket `|| true`. A scanner/tool/network failure is a failed gate, not a zero-vulnerability result.

## Production-image dispositions

`security/production-image-vulnerability-exceptions.json` is a strict, exact-match
policy for temporary final-runtime Debian findings. Every entry binds one advisory,
package, installed version, ecosystem, and image role; records a Debian tracker URL,
removal assessment, compensating controls, owner, review date, and expiry; and is
rejected if it is stale, expired, duplicated, or no longer observed. It has no
severity, package-family, or ecosystem wildcard. Application SBOM findings have no
exceptions in RC4 Batch 5B.

## Exceptions

No blanket advisory exceptions are permitted. The current Rust and Yarn exceptions
in `security/cargo-audit-exceptions.json` and
`security/yarn-audit-exceptions.json` are deliberately narrow, record their
advisories, affected dependency paths, risk assessments, and 2026-09-22 review
dates, and fail their gates if they become stale or expire. If an actionable
upstream vulnerability cannot be removed immediately, any replacement exception
must meet the same requirements and must not convert scanner failure into success.

## Deterministic invariant vs fuzzing

The deterministic state-machine campaign remains mandatory in the release/freeze lane:

```sh
PROPHET_INVARIANT_SEQUENCE_COUNT=100000 cargo test -p prophet state_machine_preserves_economic_invariants_for_thousands_of_seeds --lib --locked
```

Long-running coverage-guided fuzzing is **DEFERRED HARDENING**: this repository does not currently ship a supported fuzz-target/corpus lane. It is not represented as completed coverage.

## Static-quality scope

Rust formatting, locked workspace tests, and strict Clippy are mandatory. The repository has no existing ESLint/Prettier policy, so Batch 5 does not introduce a TypeScript formatting migration; Anchor/local-validator tests remain the TypeScript correctness gate. A new repository-wide Python formatter/linter would require unrelated cleanup, so Python lint/format migration is **DEFERRED HARDENING** rather than a false mandatory gate.
