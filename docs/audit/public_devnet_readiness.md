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
