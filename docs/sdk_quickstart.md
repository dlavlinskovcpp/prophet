# Python SDK Quickstart

This SDK is the primary interface for agent-to-agent interaction with Prophet.

## Install

```bash
cd sdk/python
pip install -e .
```

## Environment

Set these before running examples:

```bash
export RPC_URL="http://127.0.0.1:8899"
export PROPHET_PROGRAM_ID="<your_program_id>"
export PAYER_KEYPAIR_PATH="$HOME/.config/solana/id.json"
```

## Core Lifecycle API

`ProphetClient` now exposes the full MVP market lifecycle:

- `initialize_notary_config(...)`
- `update_notary_config(...)`
- `initialize_market_v2(...)`
- `place_order(...)`
- `match_orders(...)`
- `cancel_order(...)`
- `claim_refunds(...)`
- `transfer_market_authority(...)`
- `lock_market(...)` / `unlock_market(...)` / `sync_market_status(...)`
- `update_market_schedule(...)`
- `emergency_resolve_invalid(...)`
- `resolve_market_threshold(...)`
- `redeem(...)`
- `initialize_market(...)` / `resolve_market_signed(...)` / `resolve_market(...)` remain available for legacy compatibility

## Minimal Example

```python
import os
import time
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient, OrderSide, derive_market_pda, derive_notary_config_pda

client = ProphetClient(
    rpc_url=os.getenv("RPC_URL"),
    payer_keypair_path=os.getenv("PAYER_KEYPAIR_PATH"),
    program_id=os.getenv("PROPHET_PROGRAM_ID"),
)

quote_mint = Pubkey.from_string(os.environ["QUOTE_MINT"])
resolver_hash = bytes([7] * 32)

now = int(time.time())
open_ts = now - 5
lock_ts = now + 120
resolve_ts = now + 180

notary_keys = [client.payer.pubkey()]  # demo only; use real t-of-n keys in production
notary_config, _ = derive_notary_config_pda(client.payer.pubkey(), client.program_id)

try:
    client.initialize_notary_config(1, notary_keys)
except Exception:
    pass  # config may already exist for this admin

client.initialize_market_v2(
    resolver_hash=resolver_hash,
    open_ts=open_ts,
    lock_ts=lock_ts,
    resolve_ts=resolve_ts,
    notary_config=notary_config,
    quote_mint=quote_mint,
)

market, _ = derive_market_pda(resolver_hash, open_ts, client.program_id)
client.place_order(market, 0, OrderSide.BuyYes, 60_000_000, 100, quote_mint)
```

## Resolution Notes

- `resolve_market_threshold` is the primary permissionless t-of-n notary flow for v2 markets.
- The attester defaults to threshold markets and rejects legacy single-oracle markets unless `ALLOW_LEGACY_SINGLE_ORACLE=1`.
- `resolve_market_signed` remains available for older single-oracle markets and migration tooling.

## Example Scripts

- Preferred v2 relayer example: `sdk/python/examples/resolve_threshold_relayer.py`
- Legacy compatibility relayer example: `sdk/python/examples/resolve_signed_relayer.py`
- Operated matching service: `docs/matching_keeper.md`

## Attester Helper Script

The helper script supports direct proof/public-input payloads or `proof_ref` passthrough:

```bash
python scripts/resolve_market_via_attester.py <MARKET> YES \
  --proof-file ./proof.bin \
  --pi-file ./public_inputs.json
```

or:

```bash
python scripts/resolve_market_via_attester.py <MARKET> YES \
  --proof-ref "file:/abs/path/proof.bin:/abs/path/public_inputs.json"
```
