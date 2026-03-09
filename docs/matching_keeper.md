# Matching Keeper Service

`apps/matching-keeper` is the production-oriented replacement for the demo keeper scripts in `sdk/python/examples`.

It does three things:

- keeps a persistent SQLite snapshot of tracked markets and open orders
- follows Anchor logs over websocket to mark orders dirty and refresh only changed accounts
- continuously submits `match_orders` transactions for crossed books

## Run

From `apps/matching-keeper`:

```bash
poetry install
cp .env.example .env
poetry run prophet-matching-keeper
```

Required env:

- `PAYER_KEYPAIR_PATH`: signer that pays for `match_orders`
- `MARKETS`: comma-separated market pubkeys to track

Important optional env:

- `DB_PATH`: SQLite state file for order snapshots and match attempts
- `WS_URL`: websocket endpoint; defaults from `RPC_URL`
- `MAX_QTY_ATOMS`: max quantity per submitted match
- `MAX_MATCHES_PER_MARKET`: per-cycle cap to avoid one market starving others

HTTP endpoints:

- `GET /health`: process and websocket health
- `GET /markets`: runtime and persisted order-book status per market
- `GET /attempts`: recent match attempts from SQLite

## Notes

- This service is config-driven: it tracks explicit markets rather than discovering every market on-chain.
- It still relies on full snapshot refreshes as a correctness backstop even when websocket log updates are healthy.
- The next production step after this is market discovery and deployment/ops wiring, not more example scripts.
