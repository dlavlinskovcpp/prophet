# Prophet

Prophet is a Solana/Anchor **bonded-claims protocol** with:

- on-chain claim creation and bonded payout redemption
- permissionless signed claim resolution (single oracle and threshold notary modes)
- an off-chain attester service for resolver + zkTLS verification + transaction assembly
- a Python SDK for issuer/attester/redeemer automation

Legacy prediction-market CLOB paths still exist for backward compatibility, but claim flow is the default product direction.

## Table of Contents

- [Current Scope](#current-scope)
- [Architecture](#architecture)
- [Repository Layout](#repository-layout)
- [Quick Start (Localnet)](#quick-start-localnet)
- [End-to-End Claim Validation](#end-to-end-claim-validation)
- [Testing](#testing)
- [CI](#ci)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [Documentation](#documentation)
- [License](#license)

## Current Scope

### Claim MVP (active)

- `create_claim`
- `resolve_claim_signed`
- `resolve_claim_threshold`
- `redeem_claim`
- `initialize_notary_config`
- `update_notary_config`

### Legacy (still in repo)

- market/CLOB instructions and tests (`initialize_market*`, `place_order`, `match_orders`, etc.)
- market resolution paths (`resolve_market*`)

See `docs/cleanup_legacy.md` for planned staged removal.

## Architecture

### On-chain (`programs/prophet`)

- stores claim state, resolver hash, proof/public-input hashes
- verifies Ed25519 instruction(s) via instructions sysvar parsing
- supports:
  - single-signer resolution (V1 message)
  - threshold notary resolution (V2 message)

### Off-chain attester (`apps/oracle-attester`)

- loads claim + resolver definition
- evaluates resolver predicate against public inputs
- optionally verifies zkTLS evidence
- builds canonical message bytes
- signs and submits resolve tx (`/resolve-claim`)

### SDK (`sdk/python`)

- claim PDA derivation
- claim create/resolve/redeem helpers
- signer + transaction submission utilities
- fixed byte-vector tests for canonical claim messages

## Repository Layout

```text
programs/prophet/          Anchor program
tests/                     TypeScript integration tests
sdk/python/                Python SDK and examples
apps/oracle-attester/      FastAPI attester service
zktls/                     zkTLS proof client/helpers
scripts/                   helper scripts
docs/                      protocol and SDK docs
```

## Quick Start (Localnet)

### 1) Prerequisites

- Rust/Cargo
- Solana CLI
- Anchor CLI (`Anchor.toml` targets `0.32.1`)
- Node.js + Yarn
- Python 3.10+

### 2) Install JavaScript deps

```bash
yarn install --frozen-lockfile
```

### 3) Start local validator

```bash
make validator
```

### 4) Build and deploy program

```bash
make build
make deploy
```

### 5) Start attester

```bash
make attester
```

Alternative:

```bash
docker-compose -f docker-compose.localnet.yml up -d oracle-attester
```

## End-to-End Claim Validation

Run the integrated claim-stack validator:

```bash
bash scripts/validate_claim_stack.sh --skip-ts-test
```

What it does:

1. SDK smoke tests
2. `anchor keys sync` + `anchor build`
3. localnet ensure/start + deploy
4. starts attester and health-checks it
5. auto flow:
   - create claim through SDK
   - resolve through attester `/resolve-claim`
   - redeem through SDK
   - assert balances and terminal claim state

Useful options:

```bash
bash scripts/validate_claim_stack.sh --help
```

## Testing

### Anchor + TypeScript

Run all Anchor tests:

```bash
anchor test
```

Run claim-signed test only:

```bash
yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/claim_signed.ts
```

Run claim-threshold test only:

```bash
yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/claim_threshold.ts
```

Run canonical message fixed-vector test (TS):

```bash
yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/claim_message_vectors.ts
```

### Python SDK

```bash
venv/bin/pytest -q sdk/python/tests
```

Fixed-vector message tests:

```bash
venv/bin/pytest -q sdk/python/tests/test_claim_message_vectors.py
```

### Oracle Attester

```bash
# with attester deps installed (poetry or pip install ./apps/oracle-attester)
pytest -q apps/oracle-attester/tests --ignore=apps/oracle-attester/tests/test_e2e.py
```

Fixed-vector message tests:

```bash
pytest -q apps/oracle-attester/tests/test_claim_message_vectors.py
```

### zkTLS runtime guardrails

```bash
bash scripts/check_zktls.sh
```

## CI

Workflow: `.github/workflows/ci.yml`

Jobs:

- `rust-check` (cargo check + clippy)
- `python-sdk-tests`
- `oracle-attester-tests`
- `anchor-integration`:
  - builds/deploys on local validator
  - runs Anchor tests
  - runs full claim stack validator script

## Configuration

### Core local env vars

- `RPC_URL` (default `http://127.0.0.1:8899`)
- `PROPHET_PROGRAM_ID`
- `ANCHOR_WALLET` / `PAYER_KEYPAIR_PATH`

### Claim validator script env vars

- `REQUIRE_ZKTLS` (default `0` in local validation context)
- `BOND_ATOMS`
- `RESOLVER_HTTP_PORT`

### Attester env vars (selected)

- `RPC_URL`
- `PROPHET_PROGRAM_ID`
- `ORACLE_KEYPAIR_PATH`
- `RELAYER_KEYPAIR_PATH` (optional)
- `REQUIRE_ZKTLS`
- `ZKTLS_MODE`
- `RECLAIM_VERIFY_URL`

See `apps/oracle-attester/src/config.py` for the full list.

## Troubleshooting

### `--gossip-host` not recognized by `solana-test-validator`

Use `--gossip-port` and `--bind-address`.  
This repo already does that in scripts/workflows.

### Validator exits on startup (`faucet port ... already in use`)

Free the port or change it:

- default faucet port is `9901`
- see `scripts/localnet_start.sh` and `Anchor.toml` validator config

### `DeclaredProgramIdMismatch`

Program ID mismatch between deployed keypair and source `declare_id!`.

Run:

```bash
anchor keys sync -p prophet
anchor build
anchor deploy --provider.cluster localnet
```

### Attester says `Unknown account data format`

Usually indicates stale account decoder or mismatched deployment artifacts.  
Rebuild/redeploy and ensure latest SDK/attester code is running.

### Claim redeem retries show `ClaimAlreadyRedeemed` / custom `6042`

This can happen if the first transaction landed but a retry path re-submitted.  
Treat as idempotent success after confirming on-chain claim status is `Redeemed`.

### Yarn `--frozen-lockfile` failure

Lockfile drift detected. Update lockfile intentionally, commit it, then rerun CI.

## Security Notes

- zkTLS verification is off-chain in the attester.
- on-chain verification enforces signer identity and canonical message bytes.
- proof/public-input hashes are stored on-chain for auditability.
- do not commit private keys.

## Documentation

- `docs/protocol.md`
- `docs/resolver_spec.md`
- `docs/attestation_format.md`
- `docs/sdk_quickstart.md`
- `docs/cleanup_legacy.md`

## License

See `LICENSE`.
