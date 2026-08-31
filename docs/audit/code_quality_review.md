# Prophet Code Quality / Auditability Review

## Review boundary

This is an engineering-quality review, not an authorship or code-origin
classification. The review inspected the tracked contents of:

`programs/prophet`, `sdk/python`, `apps/oracle-attester`,
`apps/matching-keeper`, `scripts`, `tests`, `fuzz`, `deploy`, `.github`, and
`docs`.

The immutable security target remains `v1.0.0-rc4.7` at commit
`42351960cae1497d1a0e5dfebf46d65a72c4c5db`. No tag or historical commit is
modified by this review.

## Classified inventory

- Tracked files reviewed: **543**.
- Production/support code scope: **183 files / 31,255 LOC** consisting of
  on-chain Rust, SDK package Python, service `src` Python, and top-level
  operational scripts.
- Python AST inventory for service/support code: **152 files / 28,608 LOC /
  1,350 functions / 379 classes**. The broader production count includes the
  44 Rust source files and excludes tests and generated `target/` output.
- Largest Python modules: `operational_evidence.py` (857 LOC), `release.py`
  (935 LOC), `client.py` (793 LOC), `settlement_submission_journal.py` (661
  LOC), and `resolution_coordinator_store.py` (632 LOC).
- Largest observed function: `AttesterService.resolve_market` at 300 LOC.
- Maximum observed nesting: 7 levels in `apps/oracle-attester/src/resolver.py`
  and `apps/matching-keeper/src/service.py`.
- Maximum observed positional/keyword argument count: 19 in
  `vault_admin_attestation.py`; this is a security-evidence verifier boundary,
  not a candidate for mechanical parameter compression.
- Oversized modules (>500 LOC): **11**.
- Production Python exception handlers: **223 `except Exception`**, **one
  `except BaseException`**, and **zero bare `except`**. The `Exception`
  handlers are predominantly parser fallbacks, network normalization,
  rollback/finally paths, or outer service startup boundaries.

## Findings

### Q1-001 — stale current release labels in active documentation

- Category: documentation / auditability
- File/function: `README.md`, `docs/devnet_quickstart.md`,
  `docs/trust_model.md`, `docs/security_review_scope.md`
- Concrete smell: active guidance still identified RC4.6, its commit, revision,
  and acceptance digest after RC4.7 became the current release line.
- Why it matters: an auditor or operator following current documentation could
  review the wrong commit or acceptance basis.
- Proposed change: update only active current-release references to RC4.7,
  commit `42351960cae1497d1a0e5dfebf46d65a72c4c5db`, revision 6, and the RC4.7
  acceptance SHA. Preserve historical RC4.6 validators and immutable audit
  records.
- Behavior change: **no**.
- Security impact: reduces audit-target ambiguity.
- Recommended timing: **immediate**; safe documentation-only cleanup.

### Q1-002 — `BaseException` used for keypair parser fallback

- Category: Python error model
- File/function: `apps/oracle-attester/src/config.py:118-160`,
  `Settings._load_keypair`
- Concrete smell: the final base58 parsing fallback catches `BaseException`,
  manually re-raises only `KeyboardInterrupt` and `SystemExit`, and silently
  swallows other non-`Exception` termination signals such as `GeneratorExit`.
- Why it matters: parser fallback should normalize ordinary parse failures, not
  suppress interpreter/control-flow termination or future `BaseException`
  subclasses.
- Proposed change: catch `Exception`; ordinary parse fallback behavior is
  unchanged, while control-flow exceptions propagate naturally.
- Behavior change: **no intended behavior change**.
- Security impact: clearer failure semantics at configuration startup.
- Recommended timing: **immediate**; low-risk, testable cleanup.

### Q1-003 — keeper configuration is captured at import time

- Category: configuration / dependency boundary
- File/function: `apps/matching-keeper/src/config.py`, module initialization
- Concrete smell: `_load_dotenv_if_present()` mutates `os.environ` during import,
  while `Settings` defaults call `os.getenv` in class-body evaluation.
- Why it matters: configuration source, precedence, and initialization timing
  are hidden; tests and embedding callers cannot construct a fresh settings
  snapshot without reloading the module.
- Proposed change: move environment loading and typed parsing into explicit
  startup construction with characterization tests for `.env` precedence.
- Behavior change: potentially observable precedence/timing change.
- Security impact: configuration clarity improvement, but a careless rewrite
  could weaken production separation.
- Recommended timing: next normal configuration maintenance change; **do not
  refactor opportunistically in this review**.

### Q1-004 — operational evidence verifier is security-sensitive and large

- Category: module cohesion
- File/function: `apps/oracle-attester/src/operational_evidence.py`
- Concrete smell: 857 LOC, 40 functions, and 10 classes cover strict parsing,
  canonicalization, signature verification, trust-policy checks, and package
  validity.
- Why it matters: audit navigation and change impact are difficult.
- Classification: **cohesive-large / security-sensitive explicitness
  justified**. The nearby validation is intentionally explicit and should not
  be merged across signer/verifier trust domains.
- Proposed change: future split by evidence format and trust-policy layer only
  after characterization tests and an independence review.
- Behavior change: none intended, but refactor risk is material.
- Security impact: preserve independent validation; no current deduplication.
- Recommended timing: separate auditability project.

### Q1-005 — coordinator store combines schema, transitions, and serializers

- Category: durable state / module cohesion
- File/function: `apps/oracle-attester/src/resolution_coordinator_store.py`
- Concrete smell: 632 LOC with a 156-line function combines SQLite schema and
  migration setup, row conversion, verifier-result immutability, conflict
  transitions, settlement context binding, and runtime binding.
- Why it matters: state ownership and transition review are spread across one
  large persistence boundary.
- Classification: **security-sensitive explicitness justified**. The SQL
  transactions and transition checks are visible and should not be hidden in a
  generic state framework.
- Proposed change: future extraction of read-only row codecs from transition
  methods, with crash/replay characterization tests first.
- Behavior change: none intended; not performed here.
- Security impact: preserve transaction and anti-equivocation ordering.
- Recommended timing: separate durable-state audit.

### Q1-006 — attester orchestration function is oversized

- Category: orchestration / module cohesion
- File/function: `apps/oracle-attester/src/attester.py`,
  `AttesterService.resolve_market`
- Concrete smell: 559 LOC module and a 300-line orchestration function span
  request validation, resolver evaluation, proof fetching, verifier calls,
  cache behavior, signing, and audit output.
- Why it matters: the main path is harder to review as one transaction-like
  sequence, and unrelated transport failures can be mistaken for policy
  decisions.
- Proposed change: extract pure request/evidence assembly and leave one visible
  orchestration path; preserve verifier != signer and credential boundaries.
- Behavior change: none intended, but this is not safe without characterization
  tests.
- Security impact: high if boundaries are accidentally merged.
- Recommended timing: separate refactor with external-audit review.

### Q1-007 — active security scope previously lagged release target

- Category: auditability
- File/function: `docs/security_review_scope.md`
- Concrete smell: the scope correctly described the security boundaries but
  named the prior release identity.
- Why it matters: scope conclusions could be associated with the wrong source
  revision.
- Proposed change: synchronize the release context only; retain the substantive
  scope and non-goals.
- Behavior change: **no**.
- Security impact: removes evidence-association ambiguity.
- Recommended timing: immediate with Q1-001.

### Q2 findings

- **Q2-001:** `scripts/release.py` is 935 LOC and combines release configuration,
  manifest generation, artifact packaging, and secret-boundary checks. It is
  release tooling rather than runtime code; split only around stable command
  boundaries.
- **Q2-002:** `scripts/security_review_bundle.py` is 561 LOC and combines
  selection, redaction, manifest creation, and packaging. The security review
  boundary is explicit; improve internal naming and command-level tests before
  extracting helpers.
- **Q2-003:** `apps/oracle-attester/src/runtime_config.py` uses dense one-line
  validation statements and many small value objects. Expand only the most
  security-relevant validators in a future readability pass; do not alter
  accepted configuration semantics here.
- **Q2-004:** `sdk/python/prophet_sdk/client.py` is 793 LOC and has several
  transaction methods with broad argument surfaces. Retain the public API for
  this release line; consider typed request objects only in a major SDK change.
- **Q2-005:** `apps/matching-keeper/src/config.py` repeats environment coercion
  and validation at class-field and runtime-validation layers. This is
  accidental configuration duplication, but centralization is coupled to
  Q1-003 and is deferred.
- **Q2-006:** canonical JSON, digest, pubkey, and timestamp validators appear in
  SDK, verifier, signer, and evidence packages. Most repetition is intentional
  independent validation across security domains; do not deduplicate it merely
  because names or shapes resemble one another.
- **Q2-007:** state is represented as string constants in several durable
  journals and coordinator paths. The explicit strings aid database inspection;
  a generic enum framework would risk hiding transitions. Add transition tables
  to documentation/tests before considering a typed consolidation.

### Q3 findings

- Mixed legacy `typing.List`/`Dict` and built-in generic syntax reduces visual
  consistency but does not affect security; normalize opportunistically.
- Several comments narrate control flow, while comments explaining crash
  semantics, independent signer domains, canonical bytes, and invalid-rounding
  economics are valuable and should remain.
- Helper names such as `service`, `runtime`, `engine`, and `store` are broad,
  but their surrounding module names make the current meanings recoverable.
- Empty `__init__.py` files are package markers, not dead production modules.

## State-machine inventory

| State machine | States observed | Terminal/ambiguous states | Owner |
| --- | --- | --- | --- |
| Independent signer journal | `PREPARED`, `SIGNING`, `SIGNED`, `UNCERTAIN`, `CONFLICT` | `SIGNED`, `UNCERTAIN`, `CONFLICT` | role-local signer journal |
| Settlement submission journal | prepared, submission-started, signature-known, pending, confirmed, rejected, status-unknown | confirmed/rejected; status-unknown is intentionally ambiguous | settlement submitter journal |
| Coordinator resolution | pending, A-recorded, B-recorded, agreed, conflict | agreed/conflict | coordinator SQLite store |
| G1/G2 admission | issued/verified/rejected/replayed/cross-role-invalid | rejected/replayed | role-local admission/replay journal |
| P0C2 anti-equivocation | accepted, conflict, uncertain | conflict/uncertain | role-local signer state |
| Keeper attempts | recorded success/failure with retention pruning | historical record, not authorization | matching keeper SQLite store |
| Market lifecycle | open, locked, resolved, invalid/refundable, redeemed | resolved/redeemed/refunded | Solana program state |
| Resolver publication | canonical definition accepted/rejected by registry policy | immutable published definition or rejection | resolver registry |

The durable transitions are intentionally explicit in their security modules;
no generic framework refactor is recommended in this pass.

## Test-quality inventory

Tests cover unit, property, adversarial, integration, operational, and release
acceptance layers. The strongest cross-layer coverage is the fixed-role A/B,
G1/G2, Resolver V2, settlement arithmetic, malformed Ed25519, SQLite
durability, and localtest lanes. The primary auditability opportunities are
reducing large fixture setup and adding explicit transition tables for durable
journals; no tests were deleted or rewritten in the read-only phase.

## Safe changes selected after this inventory

1. Synchronize active documentation with the immutable RC4.7 release target.
2. Replace the one unjustified `except BaseException` parser fallback with
   `except Exception`.

No protocol, account layout, settlement wire format, authorization boundary,
persistent-state semantic, or production topology change is included.

## Pre-change classification summary

- Q0: **0**
- Q1: **7**
- Q2: **7**
- Q3: **4**
- Unjustified broad exception handlers: **1** (`BaseException`); 223 ordinary
  `Exception` handlers classified as boundary/fallback/rollback handling.
- Oversized modules (>500 LOC): **11**; no module split in this low-risk pass.

## Post-change verification

- Active release documentation now consistently identifies RC4.7, commit
  `42351960cae1497d1a0e5dfebf46d65a72c4c5db`, acceptance revision 6, and the
  acceptance SHA recorded above. Historical RC4.6 records and validators were
  not changed.
- The keypair parser fallback now catches ordinary `Exception` only. The
  ordinary parse-failure path is unchanged; interpreter control-flow
  exceptions are no longer swallowed.
- Dead production code removed: **0 files / 0 LOC**.
- Post-change Q0/Q1/Q2/Q3 classification: **0 / 7 / 7 / 4**. Oversized
  modules remain **11** because no risky split was attempted.
- Unjustified broad handlers: **0**; the remaining broad `Exception` handlers
  are boundary/fallback/rollback handlers documented in the inventory.
- Protocol, settlement wire format, account layout, authorization boundary,
  fixed-role topology, persistent-state semantics, and immutable crypto
  artifacts were not changed.

## Validation evidence

- RC4.7 acceptance command: **PASS**; oracle-attester 1,446 passed / 3
  skipped, P0C3E1 315 passed, Resolver V2 64 passed, adversarial settlement
  properties 5 passed, Rust frozen layout 1 passed, fuzz-target and operated
  config gates passed.
- Full oracle-attester: **1,446 passed, 3 skipped**.
- Full matching-keeper: **26 passed**.
- Full Python SDK: **17 passed, 2 skipped**.
- Rust workspace tests: **27 passed, 0 failed**; Rust format and Clippy with
  warnings denied: **PASS**.
- Anchor integration suite: **14 passed, 1 pending**; the pending case is the
  intentionally retired legacy single-oracle suite.
- Checked-in Python security static gate: **PASS**.
- TypeScript compiler check is not a configured package/CI gate and still has
  pre-existing generated Anchor-account typing errors; no test or generated
  interface was modified to conceal them.
- `git diff --check`: **PASS**.
