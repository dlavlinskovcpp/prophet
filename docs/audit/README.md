# Prophet external-audit package

This package is a review map, not a claim that an audit or public deployment
has occurred. Review in this order:

1. [Architecture](../architecture.md) and [sequence flows](../sequence_flows.md).
2. [Protocol state machine and frozen ABI](protocol_surface.md) and [protocol specification](../protocol.md).
3. [Custody/trust boundaries](trust_boundaries.md), then matching and accounting in [security tests](../security_testing_report.md).
4. Settlement format and threshold-notary constraints in [attestation format](../attestation_format.md).
5. Resolver V2 specification, pipeline, adapters, and multi-verifier model.
6. Verifier trust model and signer policy/Vault operations.
7. Key management, known risks, security regression evidence, and compute/migration reports.
8. Testnet deployment model, observability, operations, rollback, and release checklist.

## Reproducibility

Pinned release targets are Anchor **1.0.1**, Agave/Solana **3.1.10**, Rust
**1.89.0**, Node **20.19.6**, Yarn **1.22.22**, Python **3.11**, and Poetry
**1.8.5** (see `.github/workflows/ci.yml`). From a provisioned checkout:

```sh
cargo test --workspace --locked
anchor build
make demo
bash scripts/check_zktls.sh
```

For local validator, Vault, attester, SDK, and operated-stack integration use
the exact sequence in [the release runbook](../release_runbook.md). No private
keys, tokens, production URLs, or production resolver definitions belong in
this package.

## RC1 release gates

Read [feature freeze](feature_freeze.md), [RC1 metadata](release_candidate.md),
[machine-readable ABI baseline](v1_rc1_abi_snapshot.json), [final regression
evidence](final_security_regression.md), [public-devnet runbook](public_devnet_runbook.md),
[auditor questions](questions_for_auditors.md), and [mainnet blockers](mainnet_blockers.md)
before approving any deployment. The public-devnet configuration is a template
that must be concretized outside Git with dedicated identities and live service
evidence.
