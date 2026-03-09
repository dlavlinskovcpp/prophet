# Prophet Ops Runbook

This runbook covers the mutable local/prod-like state that Prophet operators own in this repo:

- resolver registry store: `resolver_store/`
- attester proof store: `proof_store/`
- JSONL audit logs: `audit/`
- matching keeper SQLite state: `apps/matching-keeper/state/`

## Local Stack

Bring up the full operated stack:

```bash
make localnet-up
```

Key endpoints:

- Grafana: `http://127.0.0.1:3000`
- Prometheus: `http://127.0.0.1:9090`
- Oracle attester: `http://127.0.0.1:8000`
- Remote signer: `http://127.0.0.1:8100`
- Resolver registry: `http://127.0.0.1:8200`
- Matching keeper: `http://127.0.0.1:8010`

## Monitoring

The repo provisions:

- Prometheus scrape config: `ops/monitoring/prometheus.yml`
- Alert rules: `ops/monitoring/alerts.yml`
- Grafana dashboard: `ops/monitoring/grafana/dashboards/prophet-ops.json`

Primary alerts:

- `ProphetOracleAttesterDown`
- `ProphetRemoteSignerDown`
- `ProphetResolverRegistryDown`
- `ProphetAttesterResolveErrors`
- `ProphetRemoteSignerBackendErrors`
- `ProphetMatchingKeeperDown`
- `ProphetMatchingKeeperWebsocketStale`
- `ProphetMatchingKeeperNoActiveMarkets`

## Backup

Create an ops snapshot:

```bash
make ops-backup
```

Optional custom path:

```bash
make ops-backup OUT=ops/backups/prophet-ops-manual.tar.gz
```

The archive includes the mutable runtime state plus the monitoring/config snapshot that was active when the backup was taken. Config files are included for reference; restore only rehydrates mutable state.

## Restore

Restore mutable ops state from a snapshot:

```bash
make ops-restore ARCHIVE=ops/backups/<snapshot>.tar.gz FORCE=--force
```

`--force` is required when the target state directories are already populated.

Restore rehydrates only:

- `audit/`
- `proof_store/`
- `resolver_store/`
- `apps/matching-keeper/state/`

## Incident Checklist

1. Check Grafana first for service-down or error-rate alerts.
2. Confirm `/health` and `/metrics` on the affected service.
3. Inspect the corresponding audit log in `audit/`.
4. For keeper issues, inspect `apps/matching-keeper/state/matcher.db` and `/attempts`.
5. For registry issues, verify `resolver_store/` still contains the expected resolver hashes.
6. For signer issues, verify the allowlist and signer backend health from `/health`.
7. If state corruption is suspected, stop the affected service, restore from the latest ops snapshot, and restart the stack.

## Drill Cadence

Recommended operator drills:

- monthly backup/restore rehearsal using `make ops-backup` and `make ops-restore`
- monthly Grafana/alert validation using `make localnet-up`
- before each release, verify alerts, dashboards, and writable state directories on the target environment
