# Operated Devnet Walkthrough

This guide runs Prophet in the production-shaped service model while still using Solana devnet for the on-chain program.

If you want the CI/localnet operated smoke path instead of devnet, use `make operated-smoke` after the local validator is running and the program is deployed.

If you want the repo to drive this devnet walkthrough in one command, use:

```bash
make operated-devnet ARGS="--quote-mint <mint> --payer-keypair <path> --reclaim-verify-url <url> --proof-file ./proof.bin --public-inputs-file ./public_inputs.json"
```

That command still starts the resolver registry, remote signer, and attester locally on `127.0.0.1`, but it points them at devnet and requires a real Reclaim verifier plus proof/public-input payloads that the verifier accepts.

Unlike `docs/devnet_quickstart.md`, this path uses:

- a resolver registry over HTTP
- a remote signer over HTTP
- an auth-protected attester over HTTP
- attester-driven market resolution

The services run locally on your machine, but they point at devnet for chain state and transactions.

## What This Guide Proves

This walkthrough proves the full operated path works together:

- devnet program deployment
- on-chain `NotaryConfig` and market setup
- resolver publication to the registry
- remote signer allowlist and signing path
- attester health and auth path
- attester-driven `resolve_market_threshold`

It still does not prove:

- cloud deployment
- production TLS termination
- AWS KMS or HSM integration
- backup/restore or rollback drills

For the production signer path after this walkthrough, use `docs/signer_kms_ops.md`.

## Preconditions

Before starting this guide, you should already have:

- completed `docs/devnet_quickstart.md` through deploy
- a funded devnet admin wallet
- a quote mint on devnet
- a reachable Reclaim verifier endpoint for `RECLAIM_VERIFY_URL`

Important: the attester runtime does not support mock zkTLS. You need a real verifier endpoint and proof/public-input payloads that it accepts.

If you use `make operated-devnet`, the script will:

- start the resolver registry, remote signer, and attester with auth enabled
- generate a dedicated temporary notary key unless you pass `--notary-keypair`
- publish a resolver, initialize or reuse the on-chain `NotaryConfig`, create a short-lived market, resolve it through the attester, and verify final on-chain state
- fail if the resolver does not evaluate to the requested outcome for your supplied `public_inputs.json`

By default the script will not mutate an existing mismatched `NotaryConfig` PDA for the payer wallet. Pass `--allow-update-notary-config` only if you explicitly want it to call `update_notary_config(...)` for that admin wallet.

## Ports Used

- resolver registry: `127.0.0.1:8200`
- remote signer: `127.0.0.1:8100`
- attester: `127.0.0.1:8000`

## 1. Base Environment

Export the shared on-chain settings first:

```bash
export RPC_URL="https://api.devnet.solana.com"
export PROPHET_PROGRAM_ID="$(solana address -k target/deploy/prophet-keypair.json)"
export PAYER_KEYPAIR_PATH="/tmp/prophet-devnet-smoke.json"
export QUOTE_MINT="<your-devnet-quote-mint>"
```

Sanity-check them:

```bash
echo "$RPC_URL"
echo "$PROPHET_PROGRAM_ID"
solana address -k "$PAYER_KEYPAIR_PATH"
solana balance "$(solana address -k "$PAYER_KEYPAIR_PATH")" --url devnet
```

## 2. Create A Dedicated Notary Key

Use a separate notary key instead of reusing the admin wallet:

```bash
solana-keygen new --no-bip39-passphrase --force -o /tmp/prophet-devnet-notary.json
export NOTARY_KEYPAIR_PATH="/tmp/prophet-devnet-notary.json"
export NOTARY_PUBKEY="$(solana address -k "$NOTARY_KEYPAIR_PATH")"
echo "$NOTARY_PUBKEY"
```

Create the signer allowlist file:

```bash
mkdir -p apps/oracle-attester
printf '%s\n' "$NOTARY_PUBKEY" > apps/oracle-attester/signer_allowlist.txt
```

## 3. Initialize The On-Chain NotaryConfig

Use the admin wallet as the `NotaryConfig` authority and the dedicated notary pubkey as the signer set:

```bash
cd sdk/python
python - <<'PY'
import os
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient

client = ProphetClient()
notary = Pubkey.from_string(os.environ["NOTARY_PUBKEY"])
cfg, sig = client.initialize_notary_config(1, [notary])
print(f"NOTARY_CONFIG={cfg}")
print(f"TX={sig}")
PY
cd ../..
```

Export the resulting config:

```bash
export NOTARY_CONFIG="<paste-notary-config-pubkey>"
```

If this step fails because the PDA already exists for that admin wallet, either:

- switch to a fresh admin wallet, or
- explicitly update the config with `update_notary_config(...)`

## 4. Start The Resolver Registry

Open shell A:

```bash
cd apps/oracle-attester
export APP_ENV=development
export RESOLVER_STORE_DIR=./resolver_store
export RESOLVER_REGISTRY_SERVICE_API_KEY="devnet-registry-token"
export RESOLVER_REGISTRY_REQUIRE_AUTH=1
export RATE_LIMIT_ENABLED=0
poetry install
poetry run uvicorn src.resolver_registry_main:app --host 127.0.0.1 --port 8200
```

In another shell, verify it:

```bash
curl http://127.0.0.1:8200/health
```

## 5. Start The Remote Signer

Open shell B:

```bash
cd apps/oracle-attester
export APP_ENV=development
export ALLOW_LOCAL_NOTARY_KEYS=1
export NOTARY_KEYPAIR_PATHS="$NOTARY_KEYPAIR_PATH"
export REMOTE_SIGNER_API_KEY="devnet-signer-token"
export REMOTE_SIGNER_REQUIRE_AUTH=1
export REMOTE_SIGNER_REQUIRE_ALLOWLIST=1
export REMOTE_SIGNER_ALLOWLIST_MODE=file
export REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH=./signer_allowlist.txt
export REMOTE_SIGNER_BACKEND=command
export REMOTE_SIGNER_COMMAND="python scripts/local_command_signer.py"
export RATE_LIMIT_ENABLED=0
poetry run uvicorn src.remote_signer_main:app --host 127.0.0.1 --port 8100
```

Verify it:

```bash
curl http://127.0.0.1:8100/health
```

The `loaded_pubkeys` set should include your `NOTARY_PUBKEY`.

## 6. Start The Attester

Open shell C:

```bash
cd apps/oracle-attester
export RPC_URL="$RPC_URL"
export PROPHET_PROGRAM_ID="$PROPHET_PROGRAM_ID"
export ORACLE_KEYPAIR_PATH="$PAYER_KEYPAIR_PATH"
export RELAYER_KEYPAIR_PATH="$PAYER_KEYPAIR_PATH"
export PROOF_STORE_DIR=./proof_store
export APP_ENV=development
export ZKTLS_MODE=reclaim_http
export REQUIRE_ZKTLS=1
export RECLAIM_VERIFY_URL="<your-reclaim-verify-url>"
export RECLAIM_API_KEY="<optional-reclaim-api-key>"
export PROOF_FETCH_MODE=local
export NOTARY_SIGNER_MODE=remote
export REMOTE_SIGNER_URL="http://127.0.0.1:8100/sign"
export REMOTE_SIGNER_API_KEY="devnet-signer-token"
export REMOTE_SIGNER_REQUIRE_TLS=0
export RESOLVER_REGISTRY_MODE=http
export RESOLVER_REGISTRY_URL="http://127.0.0.1:8200/resolvers"
export RESOLVER_REGISTRY_API_KEY="devnet-registry-token"
export RESOLVER_REGISTRY_REQUIRE_TLS=0
export REQUIRE_API_AUTH=1
export API_AUTH_TOKEN="devnet-attester-token"
export RATE_LIMIT_ENABLED=0
poetry run uvicorn src.main:app --host 127.0.0.1 --port 8000
```

Verify it:

```bash
curl http://127.0.0.1:8000/health
```

You should see:

- `notary_signer_mode = remote`
- resolver registry mode `http`
- remote signer health embedded in the response

## 7. Publish A Resolver

Create a resolver file:

```bash
cat > resolver.json <<'JSON'
{
  "url": "https://example.com/value",
  "method": "GET",
  "path": "data.answer",
  "predicate": "equals",
  "target_value": 42
}
JSON
```

Publish it to the registry:

```bash
python3 scripts/seed_resolver.py \
  resolver.json \
  --registry-url http://127.0.0.1:8200/resolvers \
  --api-key devnet-registry-token
```

## 8. Create A Market

Create a market using the on-chain `NotaryConfig` you initialized earlier:

```bash
python3 scripts/create_market.py \
  --resolver-file resolver.json \
  --mint "$QUOTE_MINT" \
  --notary-config "$NOTARY_CONFIG" \
  --duration 60
```

Export the created market:

```bash
export MARKET_PUBKEY="<paste-market-pubkey>"
```

Wait until the market reaches `resolve_ts`.

## 9. Prepare Proof And Public Inputs

You need proof/public-input payloads accepted by your configured `RECLAIM_VERIFY_URL`.

For the local-file path, place them at:

- `./proof.bin`
- `./public_inputs.json`

The `public_inputs.json` content must make the resolver evaluate to your requested outcome. For the example resolver above, a minimal `YES`-shaped JSON would look like:

```json
{"data":{"answer":42}}
```

Whether that is sufficient depends on your verifier. The attester will reject the request if the proof or public inputs are not accepted by the Reclaim verify endpoint.

## 10. Resolve Through The Attester

Submit the resolution request through the auth-protected attester endpoint:

```bash
python3 scripts/resolve_market_via_attester.py \
  "$MARKET_PUBKEY" YES \
  --url http://127.0.0.1:8000/resolve \
  --api-token devnet-attester-token \
  --proof-file ./proof.bin \
  --pi-file ./public_inputs.json
```

If successful, the response includes:

- transaction signature
- `proof_hash_hex`
- `public_inputs_hash_hex`
- `resolved_ts`

## 11. Verify Final State

```bash
cd sdk/python
python - <<'PY'
import os
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient

client = ProphetClient()
market = Pubkey.from_string(os.environ["MARKET_PUBKEY"])
state = client.fetch_market(market)
print(f"Market: {market}")
print(f"Status: {state.status}")
print(f"Outcome: {state.outcome}")
print(f"Proof Hash: {state.proof_hash.hex()}")
print(f"Public Inputs Hash: {state.public_inputs_hash.hex()}")
PY
cd ../..
```

## 12. Health And Audit Checks

Check metrics and health endpoints:

```bash
curl http://127.0.0.1:8200/health
curl http://127.0.0.1:8100/health
curl http://127.0.0.1:8000/health
```

Inspect audit logs:

```bash
tail -n 20 apps/oracle-attester/audit/resolver-registry.jsonl
tail -n 20 apps/oracle-attester/audit/remote-signer.jsonl
tail -n 20 apps/oracle-attester/audit/attester.jsonl
```

## Troubleshooting

### `AccountNotInitialized` for `notary_config`

You are passing a PDA that exists in address space but does not hold a valid initialized `NotaryConfig` account. Use a fresh admin wallet or reinitialize/update the config correctly.

### `already in use` during `initialize_notary_config`

That admin wallet has already derived the same `NotaryConfig` PDA. Use a fresh admin wallet or call `update_notary_config(...)` instead.

For `make operated-devnet`, the script stops on this condition unless you rerun it with `--allow-update-notary-config`.

### `Signer not allowed`

The remote signer allowlist does not include the requested pubkey. Rebuild `apps/oracle-attester/signer_allowlist.txt` with the correct `NOTARY_PUBKEY`.

### `Signer key unavailable`

The allowlist includes the pubkey, but the signer backend did not load the matching keypair. Re-check `NOTARY_KEYPAIR_PATHS` and `/health`.

### `Unauthorized`

One of the bearer tokens does not match:

- resolver registry: `RESOLVER_REGISTRY_SERVICE_API_KEY`
- remote signer: `REMOTE_SIGNER_API_KEY`
- attester: `API_AUTH_TOKEN`

### zkTLS verification failure

The attester runtime only supports `reclaim_http`. Re-check:

- `RECLAIM_VERIFY_URL`
- `RECLAIM_API_KEY`
- proof bytes
- public inputs bytes

## Next Step

After this works, the next step is to make it production-ready rather than merely devnet-ready:

- release flow: `docs/release_runbook.md`
- monitoring and recovery: `docs/ops_runbook.md`
- trust boundaries: `docs/trust_model.md`
