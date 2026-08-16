# Mainnet blockers

Mainnet is blocked until all of the following have dated evidence:

- Independent external security audit completed; all critical findings fixed.
- All high findings fixed, or explicitly accepted with strong written justification.
- Public devnet full lifecycle and conflict acceptance tests verified.
- Live monitoring and alert delivery verified.
- Dedicated signer, Vault, deployment-authority, and compromised-signer-removal drills exercised.
- Backup/restore and rollback drills exercised with retained evidence.
- RC soak period completed under defined traffic and failure criteria.
- Final security regression and reproducible artifact verification green.

Additional blockers: no formally verified core, off-chain resolver/oracle and
RPC dependencies remain, and no current evidence proves independent external
review of multi-verifier, signer, or upgrade authority assumptions.

<!-- RC2_MAINNET_BLOCKERS_START -->
## v1.0.0-rc2 mainnet blockers

Reviewed for RC2 code freeze: 2026-08-16.

RC2 local code/security verification does **not** authorize mainnet. Keep mainnet
blocked until every item below is complete with durable evidence:

- [ ] **External independent audit.** The frozen RC2 audit surface has been reviewed
  by an independent security auditor.
- [ ] **Audit findings closure.** Required findings are fixed, regression-tested,
  retested where required, and closure is documented.
- [ ] **Public-devnet deployment.** The approved candidate is deployed to public
  devnet using the production-style deployment procedure.
- [ ] **Real Vault provisioning.** Production-style Vault TLS/auth/policies/audit
  devices and Transit keys are provisioned; no deterministic-test backend or
  placeholder credential is accepted.
- [ ] **Real signer A/B provisioning.** Independent signer identities, public keys
  and key versions are bound and operational.
- [ ] **Real fee payer and RPC configuration.** Dedicated fee payer, secret storage,
  funding and approved RPC policy are live and monitored.
- [ ] **Real verifier A/B services.** Independently provisioned verifier services,
  production zkTLS trust, internal auth and failure isolation are validated.
- [ ] **Real alert delivery.** Alerts are delivered to an owned receiver and
  escalation/on-call handling is proven.
- [ ] **Live E2E settlement.** A controlled public-devnet flow reaches durable
  agreement, 2/2 signing, exact transaction construction, simulation, submission
  and explicit confirmation.
- [ ] **Restart/recovery drill.** Coordinator, signing and settlement-attempt state
  survives process restart with actual reopened durable SQLite files and no
  duplicate security-sensitive side effects.
- [ ] **Uncertain Vault recovery drill.** An interrupted/uncertain signing case is
  handled according to the fail-closed recovery policy.
- [ ] **Key rotation drill.** Real signer rotation proves existing intents remain
  pinned to their persisted A/B epochs while new intents may use the new epochs.
- [ ] **Transaction reconciliation drill.** A controlled ambiguous submission or
  equivalent interruption is reconciled without blind rebroadcast.
- [ ] **Backup/restore drill.** Coordinator, signing-journal and transaction-attempt
  databases are backed up and restored without discarding historical security
  state.
- [ ] **Monitoring/operations validation.** Metrics, logs, dashboards, alert
  delivery, secret rotation and incident procedures are exercised.
- [ ] **Soak period.** The public-devnet deployment completes an agreed soak period
  with no unresolved security/reliability blocker.
- [ ] **Mainnet-specific review.** RPC, fee payer, Vault, signer policy, monitoring,
  deployment authority, rollback and incident-response assumptions are reviewed
  for mainnet rather than inherited from devnet.
- [ ] **Explicit mainnet authorization.** A separate release decision records that
  all mainnet blockers are closed.

Local tests, simulated transactions, public-devnet templates, or code-freeze
status must not be used to mark any of the live/audit items above complete.
<!-- RC2_MAINNET_BLOCKERS_END -->
