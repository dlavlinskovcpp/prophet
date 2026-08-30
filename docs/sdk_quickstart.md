# Python SDK Quickstart

The Python SDK is the programmatic interface for agents, traders, relayers,
and developer integrations. It contains a low-level `ProphetClient` for real
transactions and a small `ProphetAgent` facade for application-owned strategy
backends.

## Install

```bash
cd sdk/python
poetry install
```

Set the connection values for a local validator or your own developer cluster:

```bash
export RPC_URL="http://127.0.0.1:8899"
export PROPHET_PROGRAM_ID="<program-id>"
export PAYER_KEYPAIR_PATH="$HOME/.config/solana/id.json"
export QUOTE_MINT="<quote-mint>"
```

The official Prophet public-devnet is currently paused and its program is not
deployed. Do not treat local or personal-devnet credentials as operated
production infrastructure.

## Current client API

`ProphetClient` currently exposes:

- `initialize_notary_config(...)`
- `rotate_notary_config(...)`
- `initialize_market_v2(...)`
- `place_order(...)` and `place_order_auto_seq(...)`
- `match_orders(...)`
- `cancel_order(...)`
- `claim_refunds(...)`
- `lock_market(...)`, `unlock_market(...)`, and `sync_market_status(...)`
- `update_market_schedule(...)`
- `set_market_fee_config(...)` and `withdraw_protocol_fees(...)`
- `resolve_market_threshold(...)`
- `redeem(...)`

## Exact 2-of-2 Market V2 example

The current Market V2 path rejects unsupported notary topologies. Use two
distinct, non-zero notary public keys:

```python
import os
import time

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from prophet_sdk import (
    ProphetClient,
    derive_market_pda,
    derive_notary_config_pda,
)

client = ProphetClient(
    rpc_url=os.environ["RPC_URL"],
    payer_keypair_path=os.environ["PAYER_KEYPAIR_PATH"],
    program_id=os.environ["PROPHET_PROGRAM_ID"],
)

notary_a = Keypair()
notary_b = Keypair()
notary_config, _ = client.initialize_notary_config(
    2, [notary_a.pubkey(), notary_b.pubkey()]
)

resolver_hash = bytes([7]) * 32
now = int(time.time())
open_ts = now - 5
lock_ts = now + 120
resolve_ts = now + 180
quote_mint = Pubkey.from_string(os.environ["QUOTE_MINT"])

client.initialize_market_v2(
    resolver_hash=resolver_hash,
    open_ts=open_ts,
    market_nonce=0,
    lock_ts=lock_ts,
    resolve_ts=resolve_ts,
    notary_config=notary_config,
    quote_mint=quote_mint,
)

market, _ = derive_market_pda(
    client.payer.pubkey(), resolver_hash, open_ts, 0, client.program_id
)
```

`NotaryConfig` is represented generally enough for protocol evolution, but
Market V2 accepts exactly threshold 2 with exactly two distinct keys. For a
developer-only direct resolution, pass both keypairs to
`resolve_market_threshold(...)` and use a separate relayer keypair when
appropriate. The production operated path keeps signer keys outside the SDK
process.

## Rotation and legacy compatibility

`update_notary_config(...)` remains in the client for ABI compatibility but is
fail-closed: it raises because an existing snapshot is immutable. It is not a
normal mutable configuration operation.

Use `rotate_notary_config(previous_notary_config, new_version, threshold,
notary_keys)` to create the next versioned snapshot. Existing markets continue
to use the snapshot they pinned at initialization; only new markets can select
the successor.

## Agent facade

The actual `ProphetAgent` facade delegates to an application-provided
`AgentBackend`:

```python
from prophet_sdk import ProphetAgent, ResolverConfig

backend = application_backend  # your AgentBackend implementation
agent = ProphetAgent(backend)

resolver = ResolverConfig(
    resolver_id="my-resolver",
    definition=canonical_resolver_definition,
    required_verifiers=("verifier-a", "verifier-b"),
    threshold=2,
)

market = agent.create_market(question="Example question", resolver=resolver)
agent.buy_yes(market, agent_id="agent-a", quantity=100, price_e8=60_000_000)
agent.buy_no(market, agent_id="agent-b", quantity=100, price_e8=40_000_000)
agent.match_orders(market)
result = agent.resolve(market)
```

The facade is an application boundary, not a replacement for the on-chain
client or the production fixed-role signer boundary.

## Resolution and accounting notes

- `resolve_market_threshold(...)` is the current threshold resolution entry
  point and requires two valid signatures for Market V2.
- Resolver V2 definitions are canonicalized and committed through a non-zero
  `resolver_hash`; permissionless commitment does not imply operated support.
- The existing settlement domain is `PROPHET_RESOLVE_V2`; the canonical message
  is exactly 235 bytes.
- `claim_refunds(amount_atoms)` claims up to the requested amount, subject to
  the available refundable balance.
- Fee configuration is frozen after the first order. Unused fee reserve is
  returned through normal refund handling.

## Verified repository examples

- Deterministic agent flow: `make demo`
- Fixed-role localtest flow: `make operated-smoke`
- Threshold relayer example: [`examples/resolve_threshold_relayer.py`](../sdk/python/examples/resolve_threshold_relayer.py)
- Market factory: [`examples/market_factory.py`](../sdk/python/examples/market_factory.py)
- Resolver V2 specification: [`resolver_spec.md`](resolver_spec.md)
