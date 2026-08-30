# Devnet Quickstart

This guide is the shortest path from a fresh checkout to a resolved Prophet market on Solana devnet.

It intentionally uses a demo `1-of-1` notary configuration so you can validate the end-to-end developer flow quickly. That is useful for smoke testing and integration work, but it is not the production trust model.

## What You Will Do

1. Build and deploy the program to devnet.
2. Create a quote mint.
3. Initialize a demo `NotaryConfig`.
4. Create a market from a resolver definition.
5. Resolve the market directly with the SDK threshold flow.

If you want the full operated path with registry, fixed-role signers, and monitoring, use this guide first and then move to `docs/ops_runbook.md` and `docs/release_runbook.md`.

## Prerequisites

- Rust/Cargo
- Solana CLI
- Anchor CLI
- Python 3.10+
- a funded devnet wallet at `~/.config/solana/id.json` or an updated `deploy/environments/devnet.json`

Point your CLI at devnet and fund the wallet:

```bash
solana config set --url https://api.devnet.solana.com
solana airdrop 2
```

## 1. Build And Deploy

Build the program:

```bash
make build
```

Deploy with the repo-supported release flow:

```bash
make release-deploy ENV=devnet TAG=devnet-smoke
```

Export the program id from the deployed keypair:

```bash
export RPC_URL="https://api.devnet.solana.com"
export PROPHET_PROGRAM_ID="$(solana address -k target/deploy/prophet-keypair.json)"
export PAYER_KEYPAIR_PATH="$HOME/.config/solana/id.json"
```

Sanity-check those exports before running any SDK command:

```bash
echo "$RPC_URL"
echo "$PROPHET_PROGRAM_ID"
solana address -k "$PAYER_KEYPAIR_PATH"
solana balance "$(solana address -k "$PAYER_KEYPAIR_PATH")" --url devnet
```

Recommended for a clean smoke path: switch to a fresh devnet wallet for market creation and resolution so you do not inherit old `NotaryConfig` PDA state from previous runs.

```bash
solana-keygen new --no-bip39-passphrase --force -o /tmp/prophet-devnet-smoke.json
solana airdrop 2 "$(solana address -k /tmp/prophet-devnet-smoke.json)" --url devnet
export PAYER_KEYPAIR_PATH="/tmp/prophet-devnet-smoke.json"
```

## 2. Create A Quote Mint

Create a devnet SPL mint to use as the market quote asset:

```bash
spl-token create-token --url devnet
```

Copy the printed mint address and export it:

```bash
export QUOTE_MINT="<paste-mint-pubkey>"
```

This quickstart does not place orders, so you do not need to mint tokens into a user ATA yet.

## 3. Initialize A Demo NotaryConfig

For the smoke path, use your payer wallet as the only notary.

From `sdk/python`:

```bash
cd sdk/python
pip install -e .
python - <<'PY'
from prophet_sdk import ProphetClient

client = ProphetClient()
cfg, sig = client.initialize_notary_config(1, [client.payer.pubkey()])
print("NOTARY_CONFIG=", cfg)
print("TX=", sig)
PY
cd ../..
```

If this step fails with `already in use` or later market creation fails with `AccountNotInitialized` for `notary_config`, your current admin wallet is reusing a stale devnet PDA. Generate a fresh smoke wallet with the commands above and retry this step.

If this step fails with `AccountNotFound` or `Attempt to debit an account but found no record of a prior credit`, the SDK is usually pointed at the wrong RPC or the payer wallet is unfunded on devnet. Re-check `RPC_URL`, `PAYER_KEYPAIR_PATH`, and the payer balance, then retry.

Export the printed `NOTARY_CONFIG` pubkey:

```bash
export NOTARY_CONFIG="<paste-notary-config-pubkey>"
```

## 4. Create A Resolver Definition

Write a simple resolver file:

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

Create a market that resolves after 60 seconds:

```bash
python3 scripts/create_market.py \
  --resolver-file resolver.json \
  --mint "$QUOTE_MINT" \
  --notary-config "$NOTARY_CONFIG" \
  --duration 60
```

The script prints the market address. Export it:

```bash
export MARKET_PUBKEY="<paste-market-pubkey>"
```

## 5. Wait Until Resolve Time

The example above uses `--duration 60`, so wait about a minute before resolving.

## 6. Resolve The Market Directly

Use the direct threshold relayer example with the same wallet acting as payer and notary:

```bash
export NOTARY_KEYPAIR_PATHS="$PAYER_KEYPAIR_PATH"
export OUTCOME="YES"
python3 sdk/python/examples/resolve_threshold_relayer.py
```

If you want to record non-zero hashes in the resolved market, set these first:

```bash
export PROOF_HASH_HEX="$(python3 - <<'PY'
import hashlib
print(hashlib.sha256(b'devnet-proof').hexdigest())
PY
)"
export PUBLIC_INPUTS_HASH_HEX="$(python3 - <<'PY'
import hashlib
print(hashlib.sha256(b'{\"data\":{\"answer\":42}}').hexdigest())
PY
)"
```

Then rerun the relayer command.

## 7. Verify Final State

Inspect the market through the SDK:

```bash
cd sdk/python
python - <<'PY'
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient
import os

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

You should see:

- `status = Resolved`
- `outcome = Yes` or whatever you chose
- non-zero `proof_hash` and `public_inputs_hash` if you set them

## What This Quickstart Proves

This flow proves that:

- the deployed program accepts v2 market creation
- `NotaryConfig` setup works
- threshold resolution works on devnet
- the SDK can drive the full market setup and resolve path

It does not prove the full operated path:

- no attester service
- no remote signer
- no resolver registry
- no matching keeper
- no monitoring stack

## Next Step

After this smoke path, the next practical step is to move to the operated path:

- full operated devnet flow: `docs/operated_devnet.md`
- one-command operated devnet runner: `make operated-devnet ARGS="--quote-mint <mint> --payer-keypair <path> --reclaim-verify-url <url> --proof-file ./proof.bin --public-inputs-file ./public_inputs.json"`
- release process: `docs/release_runbook.md`
- ops and monitoring: `docs/ops_runbook.md`
- system overview: `docs/architecture.md`
- trust boundary details: `docs/trust_model.md`
