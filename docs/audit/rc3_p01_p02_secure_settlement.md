# RC3 security remediation: P-01 + P-02

Status: implementation prepared for regression verification.

P-01 removes the production/public-devnet direct-attester settlement topology.
Production release metadata and preflight require secure-coordinator mode,
independent verifier A/B services, durable coordinator state, durable signing
and submission journals, strict 2/2, and the secure settlement service.

P-02 removes arbitrary-message production settlement authorization. The generic
remote signer is not present in production-shaped settlement Compose and fails
closed in secure-coordinator mode. The production settlement API accepts only a
durable coordinator job id. `AgreedSettlementSigner` reloads durable AGREED
state and canonical context, then the existing SigningJournal and two bound
Vault Transit signer domains authorize the exact existing canonical bytes.

No protocol bytes, Resolver V2 canonical hash, Solana instruction semantics,
upgrade/deployment authority semantics, or Anchor ABI are changed.

Verification evidence required before closing:
- full oracle-attester non-E2E suite
- verifier/coordinator/signing/recovery/settlement suites
- secure release/preflight tests
- zkTLS guardrail
- `git diff --check`
