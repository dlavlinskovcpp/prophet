# Matching Keeper Service

`apps/matching-keeper` is the operated matching service for Prophet markets. It replaces the example keepers in `sdk/python/examples` with a long-running process that can be monitored and restarted like normal infra.

It does four things:

- discovers or accepts configured markets to track
- keeps a persistent SQLite snapshot of market metadata, open orders, and match attempts
- follows order-account websocket updates and periodically resyncs full books as a correctness backstop
- continuously submits `match_orders` transactions for crossed books

## Run

From `apps/matching-keeper`:

```bash
poetry install
cp .env.example .env
poetry run prophet-matching-keeper
```

Top-level shortcuts:

```bash
cp apps/matching-keeper/.env.example apps/matching-keeper/.env
make keeper
make localnet-up
```

`make localnet-up` starts the validator, Resolver V2 registry, matching keeper,
Prometheus, and Grafana from `docker-compose.localnet.yml`. It does not start
production signer roles or a generic signing service. Verifier and coordinator
processes are separate role-specific services; the fixed-role operated smoke
path is `make operated-smoke`.

Required env:

- `PROPHET_PROGRAM_ID`: explicit target Prophet deployment; there is no historical,
  public-devnet, or localnet fallback
- `PAYER_KEYPAIR_PATH`: signer that pays for `match_orders`
- `MARKETS` when `MARKET_DISCOVERY_MODE=explicit`

Important optional env:

- `MARKET_DISCOVERY_MODE`: `explicit` or `program_scan`
- `DISCOVERY_INTERVAL_S`: how often to rescan markets
- `MAX_DISCOVERED_MARKETS`: cap for `program_scan`
- `REQUIRE_NOTARY_CONFIG`: only track v2 markets with a configured notary
- `DB_PATH`: SQLite state file for snapshots and attempts
- `WS_URL`: websocket endpoint; defaults from `RPC_URL`
- `SNAPSHOT_RESYNC_S`: full order-book refresh interval
- `MATCH_ATTEMPT_RETENTION_DAYS`: SQLite retention window for attempts
- `PRUNE_INTERVAL_S`: pruning interval
- `STALE_WS_THRESHOLD_S`: health threshold for stale websocket activity
- `MAX_QTY_ATOMS`: max quantity per submitted match
- `MAX_MATCHES_PER_MARKET`: per-cycle cap so one hot market does not starve others

## Discovery Modes

`explicit`

- Tracks only the pubkeys in `MARKETS`.
- Markets are activated only when the on-chain account is still `Open`.

`program_scan`

- Scans program accounts for `Market` accounts.
- Keeps only `Open` markets, and by default only markets with a non-default `notary_config`.
- Caps tracked markets with `MAX_DISCOVERED_MARKETS`.

Markets that disappear, resolve, lock, or otherwise stop qualifying are retired automatically. Retirement clears open orders from the runtime snapshot but preserves the market row and error reason in SQLite.

## HTTP Endpoints

- `GET /health`: process, discovery, prune, and websocket health
- `GET /markets`: merged runtime plus persisted market status
- `GET /attempts`: recent match attempts from SQLite
- `GET /metrics`: Prometheus-style text metrics for active markets, open orders, attempts, and websocket/discovery ages

## Deployment

- Container image: `apps/matching-keeper/Dockerfile`
- Compose service: `docker-compose.localnet.yml`
- Make target: `Makefile`

The compose service defaults to `MARKET_DISCOVERY_MODE=program_scan`, mounts
`./id.json` as the payer, persists SQLite state under
`apps/matching-keeper/state`, and publishes the keeper on `:8010`. The payer is
only a transaction fee payer; it is not a settlement signer.
`PROPHET_PROGRAM_ID` must be exported explicitly before starting the local compose
keeper; compose does not supply a fallback program address. If you use a different
payer keypair location, override `PAYER_KEYPAIR_PATH` in
`apps/matching-keeper/.env` or in compose env overrides.

## Monitoring

- Prometheus target: `http://matching-keeper:8010/metrics`
- Sample alert rules:
  - `ProphetMatchingKeeperDown`
  - `ProphetMatchingKeeperWebsocketStale`
  - `ProphetMatchingKeeperNoActiveMarkets`

Prometheus is exposed on `:9090` and Grafana on `:3000` in the local compose stack. The repo ships a provisioned `Prophet Ops` Grafana dashboard under `ops/monitoring/grafana/dashboards/prophet-ops.json`.

## Operational Notes

- Websocket updates are treated as a low-latency hint path. The keeper still performs periodic full snapshot refreshes.
- Match attempts are durable in SQLite and old attempts are pruned on a retention schedule.
- Market onboarding is automatic in `program_scan` mode, and the repo now includes container, compose, Prometheus, Grafana, and backup/restore wiring. Use `docs/ops_runbook.md` for incident and recovery steps.
