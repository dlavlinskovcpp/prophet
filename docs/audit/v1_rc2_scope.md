# v1.0.0-rc2 Audit Scope

Status: **RC2 audit/devnet candidate scope definition**
Date: 2026-08-16
RC1 baseline: `v1.0.0-rc1`
RC2 code-review reference HEAD: `65090dda7916eee42c0b4022be56b226be900def`

This document defines the security-review surface added since RC1. It is not a claim
that this surface has received an external independent audit.

## Scope rule

The RC2 audit surface is the RC1 program/protocol surface plus the runtime,
persistence, signing, settlement-execution, deployment-template, test, and
documentation changes listed below.

The committed RC1 → RC2 reference diff contained 89 files with 12,514 insertions
and 13 deletions. Release-hygiene fixes made after the reference HEAD are also in
scope and must be included in the final RC2 candidate before CI is considered final.

No production on-chain program, Anchor IDL, or `crates/resolver-v2` core change was
present in the committed RC1 → RC2 reference diff. The current release-hygiene
working tree changes only `programs/prophet/src/security_tests.rs` under the Rust
program tree; it does not change production program logic.

## Runtime configuration and adapter construction

Audit:

- `apps/oracle-attester/pyproject.toml`
- `apps/oracle-attester/src/runtime_config.py`
- `apps/oracle-attester/src/runtime_adapter_factory.py`
- `apps/oracle-attester/src/resolver_verifier_runtime.py`
- `apps/oracle-attester/src/resolver_v2_adapters.py`
- `apps/oracle-attester/src/independent_zktls_runtime_factory.py`

Security focus:

- production/test-mode separation;
- cluster, genesis, program-ID and runtime identity binding;
- secret references by environment variable rather than inline values;
- fail-closed rejection of missing or test-only production dependencies;
- deterministic construction of the configured adapter set.

## Signed-oracle trust

Audit:

- `apps/oracle-attester/src/signed_oracle_runtime_keys.py`
- signed-oracle portions of `apps/oracle-attester/src/runtime_config.py`
- signed-oracle portions of `apps/oracle-attester/src/resolver_v2_adapters.py`

Security focus:

- registry-backed trusted-key selection;
- resolver/key-set binding;
- key epoch and version handling;
- rejection of fixture/test registries in production;
- preservation of signed-oracle canonical bytes.

## zkTLS runtime

Audit:

- `apps/oracle-attester/src/zktls_runtime_backend.py`
- `apps/oracle-attester/src/independent_zktls_runtime_factory.py`
- relevant runtime-config/bootstrap wiring

Security focus:

- approved production backend selection;
- no deterministic-test backend in production;
- dual verifier independence;
- proof/evidence normalization and runtime verification boundaries.

## Verifier runtime services

Audit:

- `apps/oracle-attester/src/verifier_service.py`
- `apps/oracle-attester/src/verifier_service_bootstrap.py`
- `apps/oracle-attester/src/verifier_service_client.py`
- `apps/oracle-attester/src/verifier_a_main.py`
- `apps/oracle-attester/src/verifier_b_main.py`

Security focus:

- verifier A/B independence;
- request/result binding;
- internal authentication;
- timeout and malformed-response handling;
- no credential material in fingerprints or errors.

## Coordinator persistence and orchestration

Audit:

- `apps/oracle-attester/src/resolution_coordinator.py`
- `apps/oracle-attester/src/resolution_coordinator_store.py`
- `apps/oracle-attester/src/coordinator_service.py`
- `apps/oracle-attester/src/coordinator_service_bootstrap.py`
- `apps/oracle-attester/src/coordinator_main.py`

Security focus:

- durable job state;
- A/B result independence;
- AGREED/CONFLICT state transitions;
- restart behavior;
- persistence ordering;
- caller inability to override durable agreement state;
- explicit separation between coordination and signing/submission.

## Vault signing path

Audit:

- `apps/oracle-attester/src/vault_transit.py`
- `apps/oracle-attester/src/vault_transit_signer_identity.py`
- `apps/oracle-attester/src/vault_transit_threshold_signer.py`

Security focus:

- signer identity and public-key pinning;
- Vault key-version pinning;
- strict A/B 2-of-2 policy;
- local Ed25519 verification of returned signatures;
- no production deterministic Vault backend;
- no token material in durable state, fingerprints, logs, or returned artifacts.

## Anti-equivocation, persistence and restart recovery

Audit:

- `apps/oracle-attester/src/signing_journal.py`
- signing/recovery portions of `apps/oracle-attester/src/vault_transit_threshold_signer.py`
- coordinator ↔ signing linkage in `apps/oracle-attester/src/agreed_settlement_signer.py`

Security focus:

- one canonical signing scope per settlement identity;
- durable intent before Vault side effects;
- conflict detection;
- uncertain-state recovery;
- genuine SQLite reopen behavior;
- preservation of completed durable signatures;
- no silent discard of security-relevant history.

## Signer key rotation

Audit:

- key-epoch policy in `apps/oracle-attester/src/vault_transit_signer_identity.py`
- rotation/recovery handling in `apps/oracle-attester/src/vault_transit_threshold_signer.py`
- persisted signer-version binding in `apps/oracle-attester/src/signing_journal.py`
- AGREED → signing integration in `apps/oracle-attester/src/agreed_settlement_signer.py`

Security focus:

- existing intents remain pinned to persisted A/B epochs;
- restart does not reselect `latest`;
- rotation does not rewrite historical signing identity;
- signer substitution and duplicate-role configurations fail closed.

## AGREED → 2-of-2 signing integration

Audit:

- `apps/oracle-attester/src/agreed_settlement_signer.py`

Security focus:

- only durable `AGREED` jobs are signable;
- canonical settlement input is derived from durable coordinator state;
- coordinator history remains immutable;
- existing signing-journal policy remains authoritative;
- completed replay performs no additional Vault calls.

## Settlement transaction construction

Audit:

- `apps/oracle-attester/src/settlement_transaction_builder.py`
- `apps/oracle-attester/src/solana_settlement_instructions.py`

Security focus:

- exact reuse of existing `PROPHET_RESOLVE_V2` bytes;
- deterministic Ed25519 instruction ordering A then B;
- existing Prophet resolve instruction/account metas;
- fee-payer separation from resolution signers;
- real `solders==0.20.0`;
- no RPC side effects during construction.

## Settlement simulation

Audit:

- `apps/oracle-attester/src/settlement_fee_payer.py`
- `apps/oracle-attester/src/settlement_rpc.py`
- `apps/oracle-attester/src/settlement_simulation.py`

Security focus:

- trusted RPC genesis binding;
- production fee-payer key boundary;
- exact signed candidate is the candidate simulated;
- malformed RPC data fails closed;
- simulation success is not treated as settlement;
- no implicit cluster/RPC fallback;
- no automatic submission from simulation.

## Settlement submission and reconciliation

Audit:

- `apps/oracle-attester/src/settlement_submission.py`
- `apps/oracle-attester/src/settlement_submission_journal.py`
- Phase 6D3 additions in `apps/oracle-attester/src/settlement_rpc.py`
- read-only execution bindings exposed by `apps/oracle-attester/src/settlement_simulation.py`

Security focus:

- durable attempt before send;
- exact simulated transaction bytes are the submitted bytes;
- local/RPC transaction-signature identity;
- ambiguous send → reconciliation, never blind rebroadcast;
- explicit commitment policy;
- durable terminal confirmation/failure;
- restart from `PREPARED`, submission-started, ambiguous, signature-known and confirmed states;
- no Vault or verifier calls during reconciliation;
- no automatic coordinator-triggered submission.

## Tests added to the audit evidence surface

Audit/release evidence includes:

- `apps/oracle-attester/tests/test_agreed_settlement_signing_integration.py`
- `apps/oracle-attester/tests/test_coordinator_service.py`
- `apps/oracle-attester/tests/test_dual_verifier_runtime_independence.py`
- `apps/oracle-attester/tests/test_resolution_coordinator.py`
- `apps/oracle-attester/tests/test_resolution_coordinator_store.py`
- `apps/oracle-attester/tests/test_resolver_v2_adapters.py`
- `apps/oracle-attester/tests/test_resolver_verifier_runtime.py`
- `apps/oracle-attester/tests/test_runtime_adapter_factory.py`
- `apps/oracle-attester/tests/test_runtime_config.py`
- `apps/oracle-attester/tests/test_settlement_simulation.py`
- `apps/oracle-attester/tests/test_settlement_submission.py`
- `apps/oracle-attester/tests/test_settlement_transaction_construction.py`
- `apps/oracle-attester/tests/test_signed_oracle_canonical_compatibility.py`
- `apps/oracle-attester/tests/test_signed_oracle_runtime_keys.py`
- `apps/oracle-attester/tests/test_signer_key_rotation.py`
- `apps/oracle-attester/tests/test_signing_journal.py`
- `apps/oracle-attester/tests/test_signing_recovery.py`
- `apps/oracle-attester/tests/test_vault_transit.py`
- `apps/oracle-attester/tests/test_vault_transit_2of2_signing.py`
- `apps/oracle-attester/tests/test_vault_transit_signer_identity.py`
- `apps/oracle-attester/tests/test_vault_transit_single_signer.py`
- `apps/oracle-attester/tests/test_verifier_service_client.py`
- `apps/oracle-attester/tests/test_verifier_services.py`
- `apps/oracle-attester/tests/test_zktls_runtime_backend.py`

Release-hygiene portability changes to temporary-directory handling in runtime,
adapter-factory and signed-oracle compatibility tests are part of the RC2 candidate
surface.

## Deployment/runtime configuration added to scope

Audit:

- `deploy/environments/public-devnet.json`
- `deploy/operated/localtest/resolver-runtime.test.yaml`
- `deploy/operated/localtest/signed-oracle-registry.test.yaml`
- `deploy/operated/public-devnet/alerts.yml`
- `deploy/operated/public-devnet/docker-compose.yml`
- `deploy/operated/public-devnet/prometheus.yml`
- `deploy/operated/public-devnet/resolver-runtime.example.yaml`
- `deploy/operated/public-devnet/runtime.env.example`
- `deploy/operated/public-devnet/vault.hcl.example`
- `scripts/public_devnet_runtime_preflight.py`
- `.gitignore`
- `Makefile`

The public-devnet templates are configuration artifacts only. They do not prove
that Vault, signers, alert delivery, deployment, backup/restore, or live settlement
has been provisioned or validated.

## Documentation added to review scope

Audit context includes:

- `docs/audit/public_devnet_evidence.md`
- `docs/audit/public_devnet_inventory.md`
- `docs/audit/public_devnet_provisioning.md`
- `docs/audit/public_devnet_runtime_runbook.md`
- `docs/resolver_v2_agreed_signing_integration.md`
- `docs/resolver_v2_coordinator_orchestration.md`
- `docs/resolver_v2_coordinator_service.md`
- `docs/resolver_v2_runtime_adapter_factory.md`
- `docs/resolver_v2_runtime_configuration.md`
- `docs/resolver_v2_runtime_verify.md`
- `docs/resolver_v2_settlement_simulation.md`
- `docs/resolver_v2_settlement_submission.md`
- `docs/resolver_v2_settlement_transaction_construction.md`
- `docs/resolver_v2_signed_oracle_runtime_keys.md`
- `docs/resolver_v2_signer_key_rotation.md`
- `docs/resolver_v2_signing_journal.md`
- `docs/resolver_v2_signing_recovery.md`
- `docs/resolver_v2_vault_2of2_signing.md`
- `docs/resolver_v2_vault_signer_identity.md`
- `docs/resolver_v2_vault_single_signer.md`
- `docs/resolver_v2_verifier_client.md`
- `docs/resolver_v2_verifier_services.md`
- `docs/resolver_v2_zktls_runtime_backend.md`

## Explicitly outside any claim of completed audit

RC2 local verification does not establish:

- independent external audit completion;
- public-devnet deployment;
- real Vault provisioning;
- live verifier/coordinator service operation;
- real alert delivery;
- live settlement execution;
- operational backup/restore;
- restart, key-rotation, or reconciliation drills against real infrastructure;
- soak-period completion;
- closure of future independent-audit findings;
- mainnet readiness.
