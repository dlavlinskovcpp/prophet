# Prophet

Prophet is a Solana/Anchor prediction market protocol with:

- on-chain order placement, matching, refunds, and redemption
- permissionless signed resolution (single oracle and threshold notary modes)
- an off-chain attester service for zkTLS verification and resolve transaction assembly
- a Python SDK intended for agent/bot integration

## Repository Layout

```text
programs/prophet/          Anchor program
tests/                     TypeScript integration tests
sdk/python/                Python SDK and examples
apps/oracle-attester/      FastAPI attester service
scripts/                   helper scripts
docs/                      protocol and SDK docs
```

## Documentation

- `docs/protocol.md`
- `docs/resolver_spec.md`
- `docs/attestation_format.md`
- `docs/sdk_quickstart.md`

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
- Attester production mode should use `NOTARY_SIGNER_MODE=remote` with a managed signer (KMS/HSM/remote signer API).
- `/resolve` is protected by bearer auth + rate limiting; `/metrics` exposes Prometheus-format counters.
- Do not commit private keys.

## License

See `LICENSE`.
