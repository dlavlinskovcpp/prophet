# Prophet

Prophet is a Solana/Anchor prediction market protocol with:

- on-chain order placement, matching, refunds, and redemption
- authority-governed lifecycle controls for lock/unlock, schedule updates, and emergency invalidation
- permissionless signed resolution, with threshold notary v2 as the primary path and single-oracle as compatibility mode
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

Remote signer (for managed notary flow):

```bash
cd apps/oracle-attester
uvicorn src.remote_signer_main:app --host 0.0.0.0 --port 8100
```

Matching keeper:

```bash
cd apps/matching-keeper
poetry install
cp .env.example .env
poetry run prophet-matching-keeper
```

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

## Security Notes

- zkTLS proof verification is off-chain in the attester.
- On-chain program verifies signed resolution messages and stores proof/public input hashes.
- Attester production mode should use `NOTARY_SIGNER_MODE=remote` with a managed signer service; the bundled remote signer now supports `REMOTE_SIGNER_BACKEND=command` so KMS/HSM wrappers can hold key material outside the process.
- The attester defaults to threshold-notary v2 markets; set `ALLOW_LEGACY_SINGLE_ORACLE=1` only for compatibility with older single-oracle markets.
- `/resolve` is protected by bearer auth + rate limiting; `/metrics` exposes Prometheus-format counters.
- Resolver definitions can be sourced from a local directory or an HTTP resolver registry, but are always re-hashed before use.
- Both the attester and remote signer persist append-only JSONL audit logs by default.
- Remote signer endpoint is `POST /sign` with bearer auth and optional signer allowlist.
- Do not commit private keys.

## License

See `LICENSE`.
