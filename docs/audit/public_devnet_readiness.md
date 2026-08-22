# Public-Devnet Readiness Matrix — v1.0.0-rc2

Status: **code readiness review; no deployment authorization**
Date: 2026-08-16

Allowed classifications:

- **READY IN CODE** — implementation/configuration shape exists and local release
  checks support it; this does not imply live provisioning.
- **NEEDS REAL INFRA** — code path exists but requires real secrets, keys, services,
  persistent storage, funding, or operators.
- **NEEDS LIVE VALIDATION** — infrastructure or procedure must be exercised against
  public devnet or the actual deployment environment.
- **BLOCKED** — must not proceed until a preceding release/security gate is closed.

## Matrix

| Dependency | Classification | RC2 evidence | What remains |
|---|---|---|---|
| Prophet program deployment | **BLOCKED** | Program tests and Resolver V2 vectors pass locally; no production program/IDL delta was introduced by RC2 runtime work. | Do not deploy until RC2 candidate is frozen and CI gate is green. Public-devnet deployment is a separate live gate. |
| Fee payer | **NEEDS REAL INFRA** | Dedicated production fee-payer boundary and strict key-file loader exist; simulation/submission tests pass in the local matrix. | Provision a dedicated devnet fee payer, store key material outside Git, fund it, restrict permissions, and validate real signing. |
| Vault | **NEEDS REAL INFRA** | Vault Transit identity, single-signer compatibility, strict 2/2, recovery and rotation paths exist in code. | Provision real Vault storage/TLS/auth/policies/audit devices and Transit keys. |
| Signer A | **NEEDS REAL INFRA** | Role A identity/version pinning and 2/2 policy are implemented and tested. | Create real independent Vault key, bind expected public key/version, verify access policy and rotation retention. |
| Signer B | **NEEDS REAL INFRA** | Role B identity/version pinning and 2/2 policy are implemented and tested. | Create real independent Vault key, bind expected public key/version, verify access policy and rotation retention. |
| Verifier A | **NEEDS REAL INFRA** | Independent verifier service/client/runtime code exists and local tests pass. | Provision endpoint, TLS/internal auth, production zkTLS provider configuration and health/alerting. |
| Verifier B | **NEEDS REAL INFRA** | Independent verifier service/client/runtime code exists and local tests pass. | Provision independently from A; validate failure independence, endpoint identity and production zkTLS provider configuration. |
| Coordinator SQLite | **READY IN CODE** | Durable coordinator state/store and reopen/recovery tests are part of the passing Python matrix. | Mount durable storage; validate ownership, fsync/filesystem behavior, backup/restore and real restart procedure. |
| Signing journal SQLite | **READY IN CODE** | Anti-equivocation, restart/recovery and key-version persistence paths are implemented and tested. | Validate durable volume, backup/restore and crash recovery under deployed filesystem/container topology. |
| Transaction-attempt journal SQLite | **READY IN CODE** | Persist-before-send, ambiguous-send and restart reconciliation are implemented and tested. | Validate storage durability and execute a live reconciliation drill. |
| RPC endpoint | **READY IN CODE** | Public-devnet template points to devnet; preflight performed a read-only genesis query without reporting genesis/RPC/program-ID mismatch. | Decide production provider/SLA/auth policy and validate outage/rate-limit behavior. |
| Monitoring | **NEEDS REAL INFRA** | Prometheus/alert configuration templates exist. | Provision real monitoring services, persistent retention, dashboards and operational ownership. |
| Alert receiver | **NEEDS REAL INFRA** | Preflight explicitly requires `ALERT_RECEIVER_CONFIGURED=1` and currently blocks because the real receiver is not configured. | Provision real delivery target and prove receipt/escalation. |
| Backup/restore | **NEEDS LIVE VALIDATION** | SQLite persistence/reopen behavior is tested in code. | Perform an operator backup and restore of coordinator, signing-journal and attempt-journal state; prove historical security state is preserved. |
| Deployment config | **READY IN CODE** | `runtime.env.example`, `resolver-runtime.example.yaml`, compose/Vault/monitoring templates and no-broadcast preflight exist. | Replace `REPLACE_*` values only with real infrastructure values outside Git; provide production signed-oracle registry and mounted secrets. |
| Signed-oracle production registry | **NEEDS REAL INFRA** | Parser correctly rejects the current example because a valid production registry is absent. | Provision protected real registry, key bindings, backup and update procedure. |
| Live E2E settlement | **NEEDS LIVE VALIDATION** | Construction, simulation and submission/reconciliation are locally tested with deterministic test infrastructure. | Execute one controlled public-devnet end-to-end settlement after deployment approval. |
| Restart/recovery drill | **NEEDS LIVE VALIDATION** | SQLite reopen and uncertain/recovery paths pass local tests. | Kill/restart real services at representative durable states and verify no duplicate signing/submission. |
| Key rotation drill | **NEEDS LIVE VALIDATION** | Persisted-epoch rotation policy is locally tested. | Rotate real Vault signer epochs and verify old active intents resume with pinned versions. |
| Transaction reconciliation drill | **NEEDS LIVE VALIDATION** | Ambiguous-send and confirmed-state reconciliation paths are locally tested. | Exercise a controlled ambiguous/interrupt scenario on devnet and reconcile without blind rebroadcast. |
| Soak period | **BLOCKED** | No public-devnet deployment exists yet. | Begin only after real deployment, monitoring and live E2E gates are green. |

## Current preflight result

Running the checked-in public-devnet env template produced the expected fail-closed
result:

- unresolved signer policy version;
- unresolved signer A public key;
- unresolved signer B public key;
- signer keys are therefore not yet distinct real identities;
- real alert receiver is not configured.

The runtime YAML is syntactically valid. Parsing stops fail-closed at the missing
or invalid production signed-oracle registry.

These are **expected real-infrastructure blockers**. They must not be replaced with
test keys, fake services or placeholder secrets merely to make preflight green.

## Release interpretation

The public-devnet deployment itself remains blocked. RC2 may be code-freeze ready
while the items classified **NEEDS REAL INFRA** and **NEEDS LIVE VALIDATION** remain
open, provided the CODE and required CI gates are green and no unresolved code
blocker exists.

<!-- RC3_PUBLIC_DEVNET_READINESS_START -->
# Public-Devnet Readiness Update — v1.0.0-rc3

Status: **code/security gates green; deployment still requires real infrastructure
and live validation**
Date: 2026-08-17

## RC3 delta

| Dependency | RC3 classification | RC3 evidence | What remains |
|---|---|---|---|
| Prophet program identity/build | **READY IN CODE** | Source and checked-in Anchor identity are `3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE`; release build regenerated matching IDL; TEST public-devnet manifest/environment/IDL all matched. | Actual public-devnet deployment is a separate live gate. |
| Resolver V2 permanent vector | **READY IN CODE** | Permanent vector is explicitly unignored and passes cross-language Rust/Anchor coverage. | Commit the candidate through normal release workflow; do not substitute generated/temporary vectors. |
| Secure coordinator settlement | **READY IN CODE** | Direct Attester settlement remains disabled; secure application-flow lane passed 13 tests including durable agreement/recovery/submission behavior. | Provision real services and perform live public-devnet E2E. |
| SDK localnet path | **READY IN CODE** | SDK localnet E2E passed 2 tests against the deployed ephemeral CI program. | Validate against the eventual public-devnet deployment. |
| Vault strict 2/2 | **READY IN CODE** | Local real Vault Transit smoke signed with distinct A/B keys through production signer code; both were v1. | Provision real production-style Vault/TLS/auth/policies and managed A/B keys. |
| Vault key rotation | **READY IN CODE** | After rotating signer B, strict 2/2 passed again with A v1 and B v2. | Execute operator-approved rotation/recovery drill in deployed infrastructure. |
| CI settlement lane | **READY IN CODE** | Mandatory CI no longer depends on the intentionally disabled direct Attester path; it tests secure settlement flow plus strict Vault 2/2. | Obtain normal repository CI evidence after the candidate is committed by the release workflow. |
| Release secret boundary | **READY IN CODE** | Release bundle security suite passed 12/12; program keypair is excluded. | Keep deployment credentials separately supplied and outside release bundles. |
| Fee payer | **NEEDS REAL INFRA** | Code boundary exists and local transaction paths pass. | Provision dedicated key, secret storage, funding, permissions, monitoring. |
| Vault / signer A / signer B | **NEEDS REAL INFRA** | Runtime integration is green locally. | Provision real non-exportable Transit keys, TLS/auth/policies/audit and record only public bindings. |
| Verifier A / verifier B | **NEEDS REAL INFRA** | Distinct verifier runtime policy exists and secure flow tests pass. | Provision independent endpoints, trust material, credentials, health/alerting and failure isolation. |
| Signed-oracle production registry | **NEEDS REAL INFRA** | Parser fails closed on missing/invalid production registry. | Provision protected real registry and key-management procedure if adapter is enabled. |
| Monitoring / alert receiver | **NEEDS REAL INFRA** | Templates and alert-validation code exist. | Provision receiver, retention, dashboards, ownership and prove delivery/escalation. |
| Durable SQLite volumes | **NEEDS LIVE VALIDATION** | Reopen/recovery behavior is tested locally. | Validate actual deployed filesystem durability, backup/restore and crash behavior. |
| Live E2E settlement | **NEEDS LIVE VALIDATION** | Local secure pipeline and exact submission/reconciliation behavior are tested. | Execute controlled public-devnet settlement after deployment approval. |
| Restart/recovery | **NEEDS LIVE VALIDATION** | Real SQLite restart path is covered in secure application-flow tests. | Kill/restart deployed services at representative durable states. |
| Rotation/reconciliation drills | **NEEDS LIVE VALIDATION** | Local rotation and ambiguous-send policies are covered. | Exercise real operator and RPC interruption scenarios. |
| Soak | **NEEDS LIVE VALIDATION** | No public-devnet deployment exists yet. | Begin only after infrastructure, deployment, monitoring and live E2E are green. |

## Current no-broadcast preflight interpretation

The public-devnet templates remain expected to fail closed until the real signer
policy/version, managed signer public keys, production signed-oracle registry,
and alert receiver are provisioned. Those are **REAL INFRA** blockers, not
reasons to insert test credentials or re-enable legacy settlement.

The intended program keypair continuity has been checked locally: exactly one
DEVNET-only ignored program keypair derives the configured `3AUW4e…` address.
The keypair is not included in release bundles.

## Deployment interpretation

RC3 code/security freeze readiness is separable from public-devnet deployment
authorization. With no unresolved CODE blocker, the remaining public-devnet
work is classified only as **NEEDS REAL INFRA** or **NEEDS LIVE VALIDATION**.
No broadcast should occur until those deployment gates are intentionally closed.
<!-- RC3_PUBLIC_DEVNET_READINESS_END -->

<!-- RC4_BATCH5_READINESS_START -->
## RC4 Batch 5 code-readiness update

Classification date: 2026-08-21. This section separates repository/CI code readiness from deployment infrastructure.

| Gate | Classification | Evidence/policy |
|---|---|---|
| Untouched environment configs | **READY IN CODE / CLOSED** | Mandatory validation reads the four checked-in JSON files directly; no rewrite is permitted before this gate. |
| Public-devnet identity | **READY IN CODE / CLOSED** | Source, Anchor, checked-in public-devnet, generated IDL and release manifest are required to match `3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE`. |
| Secure topology/resource defaults | **READY IN CODE / CLOSED** | Structural operated validation requires verifier A/B, coordinator, secure settlement, durable state/audit mounts, no direct/generic signer path, safe XFF default, and bounded-resource settings. |
| Production images | **READY IN CODE / CLOSED** | CI builds oracle + keeper from the same repository-root Docker contexts used by operated compose and runs runtime import/dependency/dev-tool checks. |
| Dependency locks / SDK / Rust quality | **READY IN CODE / CLOSED** | Poetry lock installs, full SDK tests, Rust fmt/workspace locked tests/strict Clippy are mandatory. |
| Supply-chain baseline | **READY IN CODE / CLOSED** | Pinned Rust/Python/JS/image scanners and SPDX SBOM are mandatory; findings are not silently ignored. |
| Real verifier/Vault/RPC/fee payer/alert receiver/secrets | **NEEDS REAL INFRA** | CI uses no real operator secrets and does not substitute test credentials for public-devnet readiness. |
| Live E2E, restart/recovery, rotation, reconciliation, backup/restore, soak | **NEEDS LIVE VALIDATION** | Must be exercised against deployed public-devnet infrastructure. |
| External independent audit | **NEEDS LIVE VALIDATION** | RC4 is not externally audited. |

`PUBLIC DEVNET CODE PREFLIGHT PASSED` means repository configuration/policy is code-ready. It does **not** resolve `NEEDS REAL INFRA` or `NEEDS LIVE VALIDATION` items and does not authorize a deployment.

**RC4 is not externally audited. RC4 does not authorize mainnet.**
<!-- RC4_BATCH5_READINESS_END -->
