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
- `ProphetMatchingKeeperDirtyOrderBacklog`
- `ProphetMatchingKeeperSnapshotLag`
- `ProphetMatchingKeeperNoActiveMarkets`

Config validation:

```bash
make ops-validate-alerts
```

## Signer / KMS Checks

Use the dedicated signer runbook for full bootstrap and rotation steps:

- `docs/signer_kms_ops.md`

Operational commands:

```bash
make signer-kms-bootstrap ARGS="--region us-east-1 --key-id alias/prophet-devnet-notary-01"
make signer-dry-run ARGS="backend"
make signer-dry-run ARGS="--public-key <pubkey> service --url https://signer.example/sign --api-key <token>"
make signer-allowlist ARGS="--path /etc/prophet/devnet/signer_allowlist.txt show"
```

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

Repeatable verification:

```bash
make ops-verify-restore
```

That check stages fixture state in a temporary workspace, runs the backup script, verifies the checksum and manifest, confirms restore refuses to overwrite non-empty state without `--force`, and then validates a forced restore reproduces the original mutable state.

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
6. For signer issues, verify the allowlist and signer backend health from `/health`, then rerun `make signer-dry-run`.
7. If state corruption is suspected, stop the affected service, restore from the latest ops snapshot, and restart the stack.

## Signer Incidents

For signer-specific failures:

1. Check `/health` for `ok`, `allowlist_ready`, `aws_loaded_key_ids`, and recent audit log writes.
2. Run `make signer-dry-run ARGS="backend"` on the signer host to isolate backend or IAM/KMS issues.
3. If the HTTP path is suspect, run `make signer-dry-run ARGS="--public-key <pubkey> service --url <signer url> --api-key <token>"`.
4. If a key is compromised, remove it from the allowlist first, then update on-chain `NotaryConfig`, then re-run the dry-runs on the surviving signer set.
5. Remember that updating `NotaryConfig` bumps the version bound into `resolve_market_threshold`, so old signatures must be re-collected after emergency rotation.

## Drill Cadence

Recommended operator drills:

- weekly `make ops-validate-alerts`
- monthly `make ops-verify-restore`
- monthly Grafana/dashboard review using `make localnet-up`
- before each release, verify alerts, dashboards, and writable state directories on the target environment
