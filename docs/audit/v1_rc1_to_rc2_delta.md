# v1.0.0-rc1 → v1.0.0-rc2 Security Delta

Status: **security-relevant delta for audit/devnet review**
Date: 2026-08-16
Baseline: `v1.0.0-rc1`
RC2 reference HEAD: `65090dda7916eee42c0b4022be56b226be900def`

This is a technical delta, not a release announcement and not a claim of external
audit completion.

## Verification context

The current local release evidence includes:

- Python 3.11 runtime matrix: **475 passed, 0 failed, 5 deselected**;
- real `solders==0.20.0`;
- `solana==0.32.0`;
- Prophet Rust tests: **17 passed, 0 failed**;
- Resolver V2 Rust tests: **4 passed, 0 failed**;
- `cargo fmt --all -- --check`: pass;
- `cargo clippy --workspace --all-targets`: exit 0 with known Anchor/toolchain and
  pre-existing lint warnings;
- zkTLS guardrail audit: pass;
- `git diff --check`: pass;
- working-tree secret scan: no production secret identified;
- public-devnet preflight: fail-closed on unresolved real infrastructure, as expected.

The most recent GitHub CI evidence predates the portability cleanup and is not
treated as final RC2 CI evidence. The prior Python CI failure was isolated to
macOS-specific `/private/tmp` use in tests; the working tree removes that platform
assumption. A new GitHub CI run remains a CI gate.

## Runtime configuration

**Purpose.** Provide one typed source of runtime identity, environment, adapter,
verifier, signing and settlement-execution configuration.

**Trust boundary.** Configuration selects cluster/genesis/program identity and
production versus test dependencies. Secret values are referenced through
environment variables or external files rather than embedded in fingerprints.

**Persistence.** Runtime configuration is not authoritative protocol history.
Durable coordinator/signing/attempt databases remain separate.

**Fail-closed behavior.** Production rejects deterministic-test zkTLS/Vault paths,
test/fixture trust registries, missing required production signing dependencies,
and invalid cluster/program/runtime bindings.

**Principal tests.**

- `test_runtime_config.py`
- `test_runtime_adapter_factory.py`
- `test_resolver_verifier_runtime.py`
- `test_dual_verifier_runtime_independence.py`

**Remaining operational assumptions.** Real paths, secret mounts, verifier
endpoints, signer identities and production service topology must be provisioned
outside the repository.

## Signed-oracle runtime trust

**Purpose.** Move signed-oracle verification to an explicit trusted runtime
registry with resolver/key-set binding.

**Trust boundary.** The registry and configured binding determine which public
keys and versions may authenticate signed-oracle evidence.

**Persistence.** Registry files are operational trust configuration; they do not
rewrite canonical signed-oracle payloads.

**Fail-closed behavior.** Missing/invalid registry entries, fixture registries in
production, unsupported message versions, and key-set mismatches reject.

**Principal tests.**

- `test_signed_oracle_runtime_keys.py`
- `test_signed_oracle_canonical_compatibility.py`
- signed-oracle cases in `test_runtime_config.py`
- signed-oracle runtime verification cases

**Remaining operational assumptions.** A real production registry must be
provisioned, protected, backed up and updated under an operator-controlled key
lifecycle.

## zkTLS runtime

**Purpose.** Bind runtime verification to a configured zkTLS backend and preserve
independence between verifier services.

**Trust boundary.** Approved proof backend, provider identity, proof version and
normalized verifier result.

**Persistence.** zkTLS verification results feed coordinator state; the backend
itself is not a durable authority.

**Fail-closed behavior.** Deterministic-test backend is not accepted as production
runtime trust. Malformed/unsupported proof data rejects.

**Principal tests.**

- `test_zktls_runtime_backend.py`
- `test_dual_verifier_runtime_independence.py`
- `test_resolver_verifier_runtime.py`
- `scripts/check_zktls.sh`

**Remaining operational assumptions.** Real provider credentials/endpoints,
availability, proof-policy governance and incident response remain operational
dependencies.

## Verifier HTTP services and client

**Purpose.** Expose verifier A/B as narrow independently configured services and
consume their results through a strict internal client.

**Trust boundary.** Internal authentication, endpoint identity, request/result
binding, timeout policy and response validation.

**Persistence.** Verifier services are not the durable agreement authority.
Coordinator persistence is authoritative.

**Fail-closed behavior.** Missing credentials, malformed responses, identity or
hash mismatch, timeout, and invalid runtime configuration reject.

**Principal tests.**

- `test_verifier_services.py`
- `test_verifier_service_client.py`
- `test_dual_verifier_runtime_independence.py`

**Remaining operational assumptions.** Real service isolation, TLS, secrets,
network policy, capacity and alerting require live infrastructure validation.

## Coordinator state and orchestration

**Purpose.** Persist independent verifier results and derive durable
`AGREED`/`CONFLICT` coordinator state.

**Trust boundary.** Durable coordinator job plus independently bound verifier A/B
results. Caller-provided outcome is not authoritative once state exists.

**Persistence.** SQLite coordinator store.

**Fail-closed behavior.** Partial results remain non-agreed, conflicts remain
non-signable, mismatched result identity rejects, and persisted history is not
silently repaired.

**Principal tests.**

- `test_resolution_coordinator.py`
- `test_resolution_coordinator_store.py`
- `test_coordinator_service.py`

**Remaining operational assumptions.** Filesystem durability, database ownership,
backup/restore, process supervision and real restart drills remain operator
responsibilities.

## Vault signer identity and single-signer compatibility

**Purpose.** Bind Vault Transit signing responses to a configured signer identity,
public key and key version while retaining single-signer compatibility.

**Trust boundary.** Vault endpoint/authentication plus pinned Transit key identity
and local Ed25519 verification.

**Persistence.** Vault remains external. Durable signing state records safe public
identity/version and result state, not tokens or private keys.

**Fail-closed behavior.** Authentication/permission failures, wrong key version,
wrong public key, malformed signature or locally unverifiable signature reject.

**Principal tests.**

- `test_vault_transit_signer_identity.py`
- `test_vault_transit_single_signer.py`
- `test_vault_transit.py`

**Remaining operational assumptions.** Real Vault HA/storage, TLS, token lifecycle,
policy, audit devices, Transit keys and recovery procedures are not proven by local
tests.

## Strict Vault 2-of-2 signing

**Purpose.** Require both configured signer roles A and B for a settlement
signature bundle.

**Trust boundary.** Fixed role identity and version for each signer; no 1-of-2
fallback or role substitution.

**Persistence.** Signing journal persists the canonical intent and per-role
progress.

**Fail-closed behavior.** Duplicate identity, swapped role, missing signer,
version mismatch, corrupt response or partial completion does not produce a valid
2-of-2 result.

**Principal tests.**

- `test_vault_transit_2of2_signing.py`
- `test_vault_transit_signer_identity.py`

**Remaining operational assumptions.** Real signers must be independently
provisioned and access-controlled in Vault.

## Signing anti-equivocation and restart recovery

**Purpose.** Prevent one settlement scope from being signed for competing
canonical messages and survive process failure without unsafe replay.

**Trust boundary.** Canonical signing scope, message digest, persisted signer
epochs and durable side-effect ordering.

**Persistence.** SQLite signing journal, including durable coordinator ↔ signing
linkage.

**Fail-closed behavior.** Same scope/different digest conflicts; uncertain state
does not silently retry or advance; completed replay returns durable signatures
without new Vault calls.

**Principal tests.**

- `test_signing_journal.py`
- `test_signing_recovery.py`
- `test_agreed_settlement_signing_integration.py`

**Remaining operational assumptions.** Operational backup/restore and crash drills
must prove database state survives the actual deployment environment.

## Signer key rotation

**Purpose.** Permit new settlements to use configured new signer epochs without
changing the signer versions already bound to an existing intent.

**Trust boundary.** Persisted signer A/B key epochs are authoritative for an
existing signing intent.

**Persistence.** Key-version binding is durable in the signing journal.

**Fail-closed behavior.** Restart never reselects `latest` for an existing intent;
unconfigured historical epoch or signer substitution rejects.

**Principal tests.**

- `test_signer_key_rotation.py`
- rotation cases in `test_signing_recovery.py`
- rotation cases in `test_agreed_settlement_signing_integration.py`

**Remaining operational assumptions.** Real Vault rotation must be rehearsed with
key retention, rollback, revocation and audit-log procedures.

## AGREED → 2-of-2 integration

**Purpose.** Derive the exact settlement to sign from durable coordinator
`AGREED` state and invoke the existing signing policy.

**Trust boundary.** Durable coordinator history, not HTTP/caller settlement
overrides.

**Persistence.** Coordinator ↔ signing linkage plus existing signing journal.

**Fail-closed behavior.** `CONFLICT`, partial, unknown or internally inconsistent
jobs do not produce signing side effects.

**Principal tests.**

- `test_agreed_settlement_signing_integration.py`
- coordinator and signing recovery suites

**Remaining operational assumptions.** Service-level access control and explicit
operator invocation policy require live deployment validation.

## Settlement transaction construction

**Purpose.** Convert a completed durable 2-of-2 settlement bundle into the exact
Solana transaction candidate.

**Trust boundary.** Existing `PROPHET_RESOLVE_V2` bytes, signer A/B public
identities/signatures, expected Prophet program, fee payer and recent blockhash.

**Persistence.** Construction is read-only with respect to coordinator and signing
history.

**Fail-closed behavior.** Wrong program/cluster, incomplete signing, bundle
substitution, account/instruction mismatch or invalid solders object rejects.

**Principal tests.**

- `test_settlement_transaction_construction.py`
- canonical/golden settlement tests

**Remaining operational assumptions.** Fresh blockhash and real fee-payer
provisioning are execution-time dependencies.

## Settlement simulation

**Purpose.** Acquire trusted RPC genesis/blockhash, apply the dedicated fee-payer
signature and simulate the exact candidate before submission.

**Trust boundary.** Configured RPC genesis, expected cluster/program, dedicated
fee payer, exact transaction bytes and strict RPC response shapes.

**Persistence.** Simulation itself does not mark settlement complete or mutate
coordinator/signing state.

**Fail-closed behavior.** Genesis mismatch, malformed RPC response, simulation
program error, stale blockhash, missing production fee payer or test RPC in
production prevents readiness.

**Principal tests.**

- `test_settlement_simulation.py`

**Remaining operational assumptions.** RPC availability/quality and real fee-payer
secret storage/funding require live infrastructure.

## Settlement submission and reconciliation

**Purpose.** Submit one already simulated signed candidate with durable
persist-before-send semantics and reconcile confirmation after crashes or
ambiguous network outcomes.

**Trust boundary.** Durable signing bundle, exact transaction bytes, local
transaction signature, RPC signature/status, explicit commitment and
cluster/genesis/program identity.

**Persistence.** Separate SQLite transaction-attempt journal records candidate,
local signature, submission marker, status and terminal outcome.

**Fail-closed behavior.** Submission intent is committed before send; ambiguous
send never causes blind rebroadcast; signature mismatch/malformed status rejects;
restart reconciles before any new send; terminal confirmed/failure states are
durable.

**Principal tests.**

- `test_settlement_submission.py`
- regression coverage in simulation/construction/signing suites

**Remaining operational assumptions.** A live devnet transaction reconciliation
drill, RPC outage drill and operational runbook rehearsal are still required.

## Deployment and observability configuration

**Purpose.** Provide public-devnet templates for runtime, Vault, monitoring,
alerts and service composition plus a no-broadcast preflight.

**Trust boundary.** Templates contain public identifiers and secret references,
not production secret values.

**Persistence.** Operational files define desired deployment shape; runtime
databases and secret stores are external/mounted.

**Fail-closed behavior.** Public-devnet preflight rejects unresolved signer policy,
unresolved signer identities and absent real alert receiver. Runtime YAML parsing
rejects an absent/invalid production signed-oracle registry.

**Principal verification.**

- `scripts/public_devnet_runtime_preflight.py`
- runtime parser against `resolver-runtime.example.yaml`
- secret/test-artifact scans

**Remaining operational assumptions.** Public-devnet deployment, Vault, signers,
alerts, backup/restore, live E2E settlement and soak are not complete.

## Protocol compatibility

The RC1 → RC2 committed reference diff contains no production change under:

- `programs/`
- `target/idl`
- `Anchor.toml`
- `crates/resolver-v2`

Release-hygiene changes after the reference HEAD touch only
`programs/prophet/src/security_tests.rs` in the Rust program tree.

Therefore RC2 runtime work is expected to preserve:

- Anchor IDL and instruction discriminators;
- account layout;
- existing `resolve_market_threshold` interface;
- `PROPHET_RESOLVE_V2` canonical bytes;
- Resolver V2 canonical hashes;
- legacy resolution compatibility vectors.

Any later production change to those surfaces before tagging RC2 must reopen this
compatibility review and be treated as an RC2 audit blocker.
