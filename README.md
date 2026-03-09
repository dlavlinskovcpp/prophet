# Prophet

Prophet is a Solana/Anchor prediction market protocol with:

- on-chain order placement, matching, refunds, and redemption
- per-market protocol fee config, taker-fee accrual, and treasury withdrawal
- authority-governed lifecycle controls for lock/unlock, schedule updates, and emergency invalidation
- permissionless threshold-notary v2 resolution
- an off-chain attester service for zkTLS verification and resolve transaction assembly
- a Python SDK intended for agent/bot integration

## Repository Layout

```text
programs/prophet/          Anchor program
tests/                     TypeScript integration tests
sdk/python/                Python SDK and examples
apps/oracle-attester/      FastAPI attester service
apps/matching-keeper/      Persistent matching keeper/indexer service
scripts/                   helper scripts
docs/                      protocol and SDK docs
```

## Documentation

- `docs/protocol.md`
- `docs/resolver_spec.md`
- `docs/attestation_format.md`
- `docs/sdk_quickstart.md`
- `docs/matching_keeper.md`
- `docs/ops_runbook.md`
- `docs/release_runbook.md`

## Prerequisites

- Rust/Cargo
- Solana CLI
- Anchor CLI
- Node.js + Yarn
- Python 3.10+

## Local Development

1. Start validator:

```bash
make validator
```

2. Build and deploy program:

```bash
make build
make deploy
```

3. Start attester:

```bash
make attester
```

Alternative:

```bash
docker-compose -f docker-compose.localnet.yml up -d oracle-attester
```

Resolver registry:

```bash
cd apps/oracle-attester
poetry run uvicorn src.resolver_registry_main:app --host 0.0.0.0 --port 8200
```

Publish a resolver through the registry:

```bash
make publish-resolver RESOLVER=resolver.json RESOLVER_REGISTRY_URL=http://127.0.0.1:8200/resolvers RESOLVER_REGISTRY_API_KEY=token
```

Remote signer (for managed notary flow):

```bash
cd apps/oracle-attester
cp signer_allowlist.example.txt signer_allowlist.txt
uvicorn src.remote_signer_main:app --host 0.0.0.0 --port 8100
```

Matching keeper:

```bash
cp apps/matching-keeper/.env.example apps/matching-keeper/.env
make keeper
```

The sample keeper env expects a payer keypair at `./id.json`. Override `PAYER_KEYPAIR_PATH` if yours lives elsewhere.

Localnet infra stack with validator, resolver registry, remote signer, attester, matching keeper, Prometheus, and Grafana:

```bash
make localnet-up
```

Grafana is provisioned at `http://127.0.0.1:3000` with the `Prophet Ops` dashboard preloaded.

## Testing

Anchor tests:

```bash
anchor test
```

SDK smoke test:

```bash
cd sdk/python
pytest tests/test_smoke.py
```

zkTLS config guardrails:

```bash
bash scripts/check_zktls.sh
```

Program reliability sweep:

```bash
make reliability
```

Ops snapshot / restore:

```bash
make ops-backup
make ops-restore ARCHIVE=ops/backups/<snapshot>.tar.gz FORCE=--force
```

## Release And Deploy

Release environments are defined in `deploy/environments/*.json` for `localnet`, `devnet`, and `mainnet-beta`.

Generate a release manifest from the current build artifacts:

```bash
make release-plan ENV=devnet TAG=v0.2.3
```

Archive a rollback bundle under `releases/<TAG>/<ENV>/`:

```bash
make release-bundle ENV=devnet TAG=v0.2.3
```

Build, deploy, sync the IDL, verify the program, and archive the release bundle:

```bash
make release-deploy ENV=devnet TAG=v0.2.3
```

For the full procedure, including rollback expectations, see `docs/release_runbook.md`.

## Security Notes

- zkTLS proof verification is off-chain in the attester.
- On-chain program verifies signed resolution messages and stores proof/public input hashes.
- Attester production mode should use `NOTARY_SIGNER_MODE=remote` with a managed signer service; the bundled remote signer now supports a concrete `REMOTE_SIGNER_BACKEND=aws_kms` path for Ed25519 notary keys, while `REMOTE_SIGNER_BACKEND=command` remains available for other KMS/HSM wrappers.
- The repo now includes a canonical resolver registry service (`src.resolver_registry_main:app`) with immutable publish/load semantics, bearer auth, Prometheus metrics, and append-only audit logs.
- The attester only supports threshold-notary v2 markets.
- `/resolve` is protected by bearer auth + rate limiting; `/metrics` exposes Prometheus-format counters.
- Matching keeper exposes `/health` and `/metrics`, and the local compose stack now includes Prometheus plus sample alert rules.
- Resolver definitions can be sourced from a local directory or an HTTP resolver registry, are always re-hashed before use, and are cached with stale-on-error fallback for transient registry outages.
- The local compose stack exercises the production-shaped path: attester -> remote signer over HTTP and attester -> resolver registry over HTTP.
- The attester, remote signer, and resolver registry persist append-only JSONL audit logs by default.
- Remote signer endpoint is `POST /sign` with bearer auth and a signer allowlist; for command/KMS backends that allowlist is required in production.
- The AWS KMS backend preloads configured Ed25519 key IDs, derives Solana pubkeys from `GetPublicKey`, and signs raw resolution messages with `Sign`.
- Release bundles now archive the program binary, IDL, TS types, and release manifest for rollback.
- Market authorities can set a treasury recipient plus protocol fee bps before the first order. Fee reserve is prefunded with each order, fees accrue only on taker executions, and unused reserve is returned through normal refund flows.
- Do not commit private keys.

## License

See `LICENSE`.
