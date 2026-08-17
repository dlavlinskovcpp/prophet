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

<!-- RC3_MAINNET_BLOCKERS_START -->
## v1.0.0-rc3 mainnet blockers

Reviewed for RC3 security freeze: 2026-08-17.

RC3 closes the reviewed code/CI security blockers but **does not authorize
mainnet**. The remaining blockers are external review, real infrastructure, and
live operational validation:

- [ ] Independent external security audit of the frozen RC3 surface and closure
  or explicit acceptance of required findings.
- [ ] Approved public-devnet deployment using the RC3 release procedure and the
  intended DEVNET-only identity `3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE`.
- [ ] Production-style Vault with TLS, authentication, least-privilege policies,
  audit devices, durable storage, and two independent non-exportable signer keys.
- [ ] Independent verifier A/B services with production zkTLS trust, internal
  authentication, failure isolation, monitoring, and owned operations.
- [ ] Protected production signed-oracle registry/key bindings where that adapter
  is enabled.
- [ ] Dedicated fee payer, approved RPC provider/policy, secret storage, funding,
  monitoring, and outage/rate-limit handling.
- [ ] Real monitoring, alert delivery, escalation/on-call ownership, retention,
  and incident procedures.
- [ ] Controlled public-devnet secure-settlement E2E through durable AGREED state,
  strict 2/2 Vault signing, exact transaction construction, simulation,
  submission, and explicit confirmation.
- [ ] Deployed restart/recovery drill for coordinator, signing journal, and
  transaction-attempt journal without duplicate signing or submission.
- [ ] Fail-closed uncertain-signing recovery drill with real Vault/operator
  conditions.
- [ ] Real signer key-rotation drill proving historical intents remain pinned to
  persisted epochs while new intents use the approved successor epoch.
- [ ] Controlled ambiguous-submission reconciliation drill without blind resend.
- [ ] Backup/restore drill preserving coordinator, signing, and submission
  security history.
- [ ] Public-devnet soak period under defined traffic/failure criteria.
- [ ] Mainnet-specific program identity and deployment-authority plan. The
  DEVNET-only `3AUW4e…` identity must not be inherited for mainnet.
- [ ] Mainnet-specific Vault/signer/RPC/fee-payer/monitoring/rollback/incident
  review and explicit final authorization.

Local Vault, local-validator, simulated transaction, and code-freeze evidence
must not be used to mark these live/mainnet items complete.
<!-- RC3_MAINNET_BLOCKERS_END -->
