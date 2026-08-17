# v1.0.0-rc3 security-freeze scope

Date: 2026-08-17
Base reviewed commit: `7879d0818667905fa7b2ab1e185d446ea7f04d8e`

## In scope

RC3 security freeze covers the full release-critical path rather than only the
on-chain program:

- `programs/prophet` state, instructions, arithmetic, attestation validation,
  PDA derivation and canonical resolution message behavior;
- `crates/resolver-v2` canonicalization/hashing and the permanent cross-language
  vector;
- Python SDK transaction construction, PDA/API compatibility, and localnet E2E;
- oracle-attester verifier/coordinator, secure-settlement, Vault Transit,
  signing-journal, transaction construction/simulation/submission, and recovery
  paths;
- operated public-devnet topology/runtime policy, persistent state boundaries,
  monitoring/alert templates, and no-broadcast preflight;
- release bundling and recursive secret-boundary enforcement;
- mandatory CI lanes used to claim release/security regression coverage.

## Security invariants

The freeze assumes and verifies the following code invariants:

1. Public settlement is secure-coordinator only. Direct Attester settlement and
   legacy generic signing are not fallback paths.
2. Two distinct verifier identities must produce an AGREED durable coordinator
   job before signing.
3. Settlement context and Solana runtime identity are durably bound to that job.
4. Two distinct pinned Vault signer identities are required. One-of-two,
   duplicate identity, wrong key version, wrong message, invalid signature, or
   uncertain recovery fails closed.
5. Signing intent is durable before security-sensitive signing proceeds, and
   restart recovery reuses the persisted signer epochs.
6. Exact transaction bytes are prepared and durably marked before send;
   ambiguous submission is reconciled rather than blindly rebroadcast.
7. Resolver V2 canonical bytes/hashes remain frozen and cross-language tested.
8. Markets pin immutable NotaryConfig snapshots.
9. Market lock and emergency-invalid boundaries use chain time.
10. Release artifacts contain public deployment material only and never embed a
    program deployment keypair or other Solana secret-key array.

## RC3 release identity

The intended public-devnet program address is:

`3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE`

RC3 synchronizes this not-yet-deployed devnet identity across source,
`Anchor.toml`, generated IDL, public-devnet environment metadata, runtime
configuration, and release manifest evidence. This is a predeployment identity
sync, not a migration of live public-devnet state.

CI deliberately creates an ephemeral local program keypair and runs
`anchor keys sync` inside the CI checkout; local E2E therefore remains
independent of the checked-in public-devnet address.

## Compatibility boundaries

Account binary layouts, existing instruction discriminators, Resolver V2
canonical serialization/hashes, and the 235-byte `PROPHET_RESOLVE_V2` message
remain unchanged by the RC3 freeze-specific remediation.

P-05 is an additive trust-root evolution: v1 NotaryConfig PDA compatibility is
preserved; version 2+ snapshots add the version seed; `rotate_notary_config` is
additive; legacy update remains present but fail-closed.

Changing the intended public-devnet program ID necessarily changes actual PDA
addresses on that cluster. Because the RC3 public-devnet program has not yet
been deployed, no on-chain state migration is required there. Mainnet must not
reuse the DEVNET-only identity by implication.

## Test/review evidence in scope

RC3 records green evidence for strict Rust formatting/tests/Clippy, the 100k
state-machine campaign, Anchor/local-validator integration, secure-settlement
application flow, SDK localnet E2E, live local Vault Transit strict 2/2 and
post-rotation 2/2, release-bundle secret inspection, public-devnet
build/IDL/manifest identity consistency, recovery/restart behavior, and
P-01…P-07 closure re-checks.

The retired legacy single-oracle Anchor suite remains intentionally pending and
is not treated as missing coverage.

## Out of scope for code freeze

The following are not code-freeze failures and are not authorized by this
document:

- provisioning or use of real public-devnet Vault credentials/Transit keys;
- production verifier A/B endpoints, credentials, or zkTLS provider operation;
- production signed-oracle registry and key-management operations;
- public-devnet program deployment or market/settlement broadcast;
- dedicated fee-payer funding/operations beyond existing preflight evidence;
- real alert receiver, dashboards, escalation ownership, and retention;
- live restart, ambiguous-send, key-rotation, backup/restore and soak drills;
- external independent security audit;
- any mainnet deployment, key provisioning, program identity choice, migration,
  or authorization.

Those items remain tracked as REAL INFRA or LIVE VALIDATION blockers.
