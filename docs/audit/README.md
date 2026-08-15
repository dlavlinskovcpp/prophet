# Prophet external-audit package

This package is a review map, not a claim that an audit or public deployment
has occurred. Review in this order:

1. [Protocol surface](protocol_surface.md) and [protocol specification](../protocol.md): establish the frozen ABI and state commitments.
2. [Architecture](../architecture.md), [sequence flows](../sequence_flows.md), and [trust boundaries](trust_boundaries.md): trace custody and resolution.
3. [Resolver V2 specification](../resolver_v2_spec.md), [attestation pipeline](../resolver_v2_attestation_pipeline.md), and [multi-verifier model](../resolver_v2_multi_verifier.md): review off-chain decision inputs.
4. [Threat model](../trust_model.md), [known risks](known_risks.md), and [regression matrix](security_regression_matrix.md): assess residual exposure and test coverage.
5. [Security testing report](../security_testing_report.md), [compute report](../compute_report.md), and [Anchor migration report](../migration/anchor_1_0_compatibility_report.md): reproduce claims.
6. [Testnet deployment](testnet_deployment.md), [key management](key_management.md), [observability](observability.md), [operations runbook](../ops_runbook.md), and [release checklist](release_checklist.md): review operational readiness.

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
