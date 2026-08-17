# v1 RC2 → RC3 security delta

Date: 2026-08-17
Base reviewed commit: `7879d0818667905fa7b2ab1e185d446ea7f04d8e`
Purpose: RC3 security-freeze delta and compatibility record. This document does
not authorize public-devnet or mainnet deployment.

## Security findings status

| Finding | RC3 status | Closure evidence |
|---|---|---|
| P-01 | **CLOSED** | Production settlement is secure-coordinator only; legacy direct/generic signing is disabled. |
| P-02 | **CLOSED** | Secure settlement API accepts only `coordinator_job_id`; canonical settlement fields/signatures cannot be supplied by HTTP. |
| P-03 | **CLOSED** | Local proof fetch is path-confined, repeatedly decoded, traversal/symlink resistant, inode-consistent, and fail-closed. |
| P-04 | **CLOSED** | Lock uses chain `Clock`; manual lock requires `now >= lock_ts`. |
| P-05 | **CLOSED** | NotaryConfig is immutable by snapshot; rotation creates the exact successor version and markets pin the exact snapshot. |
| P-06 | **CLOSED** | Schedule update is allowed only before activity and must preserve future/ordered timestamps. |
| P-07 | **CLOSED** | Release bundles sanitize secret references, exclude program keypairs, reject secret-shaped files, and recursively reject Solana secret arrays. |

Previously recorded closure verdicts remain authoritative:

- `P-01/P-02 SECURE SETTLEMENT CUTOVER PASSED`
- `P-03 PROOF FETCH SANDBOX PASSED`
- `P-04 P-06 MARKET TIMING HARDENING PASSED`
- `P-05 IMMUTABLE TRUST ROOT PASSED`
- `P-07 RELEASE BUNDLE SECRET REMOVAL PASSED`

## RC3 code/release delta

RC3 freeze review identified and remediated four release-reproducibility or CI
drifts without weakening the settlement security model:

1. The permanent Resolver V2 vector was present locally but hidden by the global
   `*.json` ignore. RC3 explicitly unignores
   `resolver-v2/test-vectors/v2.json`; the permanent vector SHA-256 is
   `b2f9c94f2b8ace5d4fb0defa6de908a979f0dbc88bbcd464fcc0fb2e231ef4c3`.
2. Strict Clippy was blocked by generated Anchor/Solana cfg diagnostics and
   narrow lint-only warnings. RC3 adds non-semantic lint allowances only; no
   protocol arithmetic or wire behavior changes.
3. The intended, not-yet-deployed public-devnet program identity
   `3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE` is synchronized into
   `declare_id!` and checked-in `Anchor.toml`. A release build regenerated an IDL
   with that address and a TEST public-devnet bundle with the same identity.
4. Mandatory CI still exercised the retired direct Attester settlement path.
   RC3 replaces that stale lane with secure-settlement application-flow tests
   and a live local Vault Transit strict-2/2 smoke. The smoke is repeated after
   rotating signer B from key version 1 to version 2.

The secure settlement cutover is not rolled back. Direct Attester settlement
continues to fail closed.

## Production secure settlement pipeline

The reviewed production path is:

`canonical resolver evidence → verifier A → durable A result → verifier B →
durable AGREED coordinator job → immutable settlement context/runtime binding →
SigningJournal intent → pinned Vault signer A → pinned Vault signer B → durable
2/2 bundle → unsigned transaction construction → exact Ed25519 A/B instructions
+ Prophet resolve instruction → fee-payer signing/simulation → PREPARED durable
attempt → SUBMISSION_STARTED durable marker → exact-byte send → signature
reconciliation → CONFIRMED / FAILED_FINAL / STATUS_UNKNOWN`.

Conflict or partial coordinator state stops before signing. Ambiguous submission
does not trigger blind rebroadcast. Restart recovery reuses durable coordinator,
signing, and submission state.

## Freeze evidence

| Gate | RC3 evidence |
|---|---|
| `cargo fmt --all --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace --locked` | Prophet **22 passed**; resolver-v2 **4 passed**; doctests 0 failed |
| 100k state-machine campaign | **100,000 sequences × 96 actions = 9.6M modeled actions**, PASS |
| Anchor/local-validator | **13 passing, 1 intentionally pending retired legacy suite** |
| Secure settlement application-flow lane | **13 passed** |
| SDK localnet E2E | **2 passed** |
| Live local Vault Transit strict 2/2 | PASS with distinct A/B keys at v1 |
| Live local Vault rotation | PASS after signer B rotation to v2; strict 2/2 still required |
| Release-bundle secret boundary | **12 passed** |
| Public-devnet build/IDL/bundle identity | source, Anchor config, IDL, environment and manifest all matched `3AUW4e…` |
| P-05 account-layout / Resolver V2 compatibility checks | PASS |
| Backup/restore and alert-validation code lanes | PASS in RC3 freeze matrix |

The local Vault smoke uses the production Vault Transit client and threshold
signer code. It is evidence for code/runtime integration only; it is not evidence
that public-devnet Vault, policies, credentials, or operator procedures exist.

## Compatibility matrix

| Surface | RC3 compatibility | Notes |
|---|---|---|
| Program ID | **CHANGED for intended public-devnet release identity** | Historical checked-in identity `913Xp7…` is replaced by intended not-yet-deployed devnet identity `3AUW4e…`. No live public-devnet migration exists because the program is not deployed there. |
| Market binary layout | **UNCHANGED** | No RC3 layout change. |
| NotaryConfig binary layout | **UNCHANGED** | P-05 snapshot versioning does not change account layout. |
| Existing instruction discriminators | **UNCHANGED** | Legacy `update_notary_config` keeps ABI/discriminator but fails closed. |
| NotaryConfig PDA seeds | **ADDITIVE EXTENSION** | v1 remains `[b"notary_config", admin]`; v2+ adds LE version. Program-ID change necessarily changes actual PDA addresses on public devnet. |
| `PROPHET_RESOLVE_V2` canonical bytes | **UNCHANGED** | 235-byte canonical message remains frozen. |
| Resolver hashes/serialization | **UNCHANGED** | Permanent cross-language vector remains authoritative. |
| Public instruction set / IDL | **ADDITIVE** | P-05 adds `rotate_notary_config`; RC3 identity sync changes IDL address only. |
| SDK API | **ADDITIVE** | Snapshot/version/rotation helpers are additive; legacy update helper fails closed. |
| Public-devnet state migration | **NONE** | Intended RC3 public-devnet identity has not been deployed, so there is no live state to migrate. |
| Mainnet identity | **NOT DERIVED FROM DEVNET** | `3AUW4e…` is DEVNET-only. Mainnet requires an independent program identity/provisioning decision. |

Historical RC1/RC2 audit and migration snapshots that record `913Xp7…` remain
historical evidence and should not be rewritten.

## Remaining deployment blockers

No remaining item identified by this RC3 freeze review requires weakening or
changing the closed P-01…P-07 code paths. Remaining public-devnet blockers are
real infrastructure or live-validation work: production Vault/TLS/auth/policies,
two managed signer identities, two independent verifier services, production
zkTLS/signed-oracle trust material, dedicated fee payer/RPC policy, monitoring
and alert delivery, durable-volume operational validation, controlled live E2E,
restart/recovery, rotation/reconciliation drills, backup/restore, and soak.

Mainnet remains separately blocked and requires its own identity, infrastructure,
external review, live evidence, and explicit authorization.
