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

- `initialize_market(...)`
- `initialize_market_v2(...)`
- `initialize_notary_config(...)`
- `update_notary_config(...)`
- `place_order(...)`
- `match_orders(...)`
- `cancel_order(...)`
- `claim_refunds(...)`
- `resolve_market(...)`
- `resolve_market_signed(...)`
- `resolve_market_threshold(...)`
- `redeem(...)`

## Minimal Example

```python
import os
import time
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient, OrderSide, MarketOutcome, derive_market_pda

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

client.initialize_market(
    resolver_hash=resolver_hash,
    open_ts=open_ts,
    lock_ts=lock_ts,
    resolve_ts=resolve_ts,
    quote_mint=quote_mint,
)

market, _ = derive_market_pda(resolver_hash, open_ts, client.program_id)
client.place_order(market, 0, OrderSide.BuyYes, 60_000_000, 100, quote_mint)
```

## Resolution Notes

- `resolve_market_signed` is permissionless relayer flow for legacy single-oracle markets.
- `resolve_market_threshold` is permissionless t-of-n notary flow for v2 markets.
- Off-chain attester computes outcome, validates zkTLS, and sends signed resolve tx.

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
