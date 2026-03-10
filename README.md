# Prophet

Prophet is a Solana prediction market protocol built for agent and bot execution. Trading, matching, custody, refunds, redemption, fee accounting, and market lifecycle controls live on-chain. Market resolution uses a v2 threshold-notary flow: an off-chain attester verifies zkTLS/public inputs against a resolver definition, notaries sign a canonical resolve message, and anyone can submit the final on-chain resolve transaction.

## What Prophet Includes

- an Anchor program for market lifecycle, order placement, matching, refunds, redemption, and protocol-fee accounting
- a Python SDK for market creation, trading, governance, and threshold resolution flows
- an oracle attester service for resolver evaluation, zkTLS verification, and resolve transaction assembly
- a resolver registry service for canonical resolver definition storage and retrieval
- a remote signer service with AWS KMS and command-backend support for managed notary keys
- a persistent matching keeper for off-chain order discovery and `match_orders` submission

## System Model

1. A market is created on-chain with a `resolver_hash`, trading schedule, and `NotaryConfig`.
2. Traders place and match orders entirely on-chain.
3. The attester loads the canonical resolver definition, verifies public inputs and zkTLS proof material, and prepares the canonical v2 resolve message.
4. Distinct notaries sign that message, and anyone can submit `resolve_market_threshold`.
5. The program verifies threshold signatures, stores `proof_hash` and `public_inputs_hash`, and settles refunds and redemption on-chain.

## Trust Model

- Matching, custody, fee accrual, lifecycle controls, and payout settlement are enforced on-chain.
- zkTLS cryptographic verification is off-chain in the attester; the chain stores hashes for auditability rather than re-running proof verification.
- Resolver definitions are identified on-chain by `resolver_hash` and should come from a canonical registry source.
- Resolution is permissionless to submit, but not trustless: it depends on the configured notary threshold and the operated attester/signer/registry path.
- Prophet supports v2 threshold-notary markets only.

## Read This Next

- System architecture: `docs/architecture.md`
- Trust model and security boundaries: `docs/trust_model.md`
- Fastest deploy-to-resolution walkthrough: `docs/devnet_quickstart.md`
- Reader FAQ and glossary: `docs/faq.md`
- End-to-end sequence diagrams: `docs/sequence_flows.md`
- Protocol and account model: `docs/protocol.md`
- Resolver schema and hashing: `docs/resolver_spec.md`
- Resolution message format: `docs/attestation_format.md`
- Python SDK usage: `docs/sdk_quickstart.md`
- Matching service operations: `docs/matching_keeper.md`
- Monitoring, backup, and recovery: `docs/ops_runbook.md`
- Release and rollback process: `docs/release_runbook.md`

## Repository Layout

```text
programs/prophet/          Anchor program
tests/                     TypeScript integration tests
sdk/python/                Python SDK and examples
apps/oracle-attester/      Attester, resolver registry, and signer services
apps/matching-keeper/      Persistent matching keeper/indexer service
scripts/                   Helper scripts
docs/                      Protocol, SDK, ops, and release docs
```

## Prerequisites

- Rust/Cargo
- Solana CLI
- Anchor CLI
- Node.js + Yarn
- Python 3.10+

## Local Development

For the full operated local stack:

```bash
make localnet-up
make build
make deploy
```

`make localnet-up` starts the validator, resolver registry, remote signer, attester, matching keeper, Prometheus, and Grafana from `docker-compose.localnet.yml`.

If you only want the program loop, use:

```bash
make validator
make build
make deploy
```

Publish a resolver through the registry:

```bash
make publish-resolver RESOLVER=resolver.json RESOLVER_REGISTRY_URL=http://127.0.0.1:8200/resolvers RESOLVER_REGISTRY_API_KEY=token
```

Grafana is provisioned at `http://127.0.0.1:3000` with the `Prophet Ops` dashboard preloaded.

## Testing

Primary test paths:

```bash
anchor test
make reliability
cd sdk/python && pytest tests/test_smoke.py
```

zkTLS guardrail audit:

```bash
bash scripts/check_zktls.sh
```

Ops snapshot / restore:

```bash
make ops-backup
make ops-restore ARCHIVE=ops/backups/<snapshot>.tar.gz FORCE=--force
```

## Release And Ops

Release environments live under `deploy/environments/*.json` for `localnet`, `devnet`, and `mainnet-beta`.

Common release commands:

```bash
make release-plan ENV=devnet TAG=v0.2.3
make release-bundle ENV=devnet TAG=v0.2.3
make release-deploy ENV=devnet TAG=v0.2.3
```

For the actual release flow, rollback expectations, monitoring, and recovery procedures, use:

- `docs/release_runbook.md`
- `docs/ops_runbook.md`

## Security Notes

- Use `NOTARY_SIGNER_MODE=remote` in production.
- The bundled remote signer supports `REMOTE_SIGNER_BACKEND=aws_kms` for managed Ed25519 notary keys and `REMOTE_SIGNER_BACKEND=command` for other KMS/HSM wrappers.
- Resolver definitions are always re-hashed before use and can be loaded from a local directory or HTTP registry.
- The attester, remote signer, and resolver registry persist append-only JSONL audit logs by default.
- Market authorities can set a fee recipient and protocol fee bps before the first order only.
- Do not commit private keys.

## License

See `LICENSE`.
