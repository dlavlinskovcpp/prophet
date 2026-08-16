# Production Checklist

Use this as a preflight before shipping to a real cluster. It assumes you already validated the devnet and operated-devnet paths.

## Release and Rollback
- release tag chosen and `scripts/release.py plan/bundle/deploy` run for the target env
- upgrade authority and program id confirmed for the target cluster
- rollback bundle archived and accessible (program.so, IDL, types, config, git sha)
- change freeze window and on-call owners set

## Signer / Vault
- `NOTARY_SIGNER_MODE=remote` in attester
- remote signer backend set to Vault Transit or another managed signer path; `make signer-vault-bootstrap` output archived for the target release
- `make signer-dry-run ARGS="backend"` passes on the signer host
- `make signer-dry-run ARGS="--public-key <pubkey> service --url <https signer url> --api-key <token>"` passes against the live service path
- signer allowlist present, loaded, and rotated with `make signer-allowlist`; current and next key sets documented
- Vault policies/tokens scoped to the notary keys only; audit logging enabled

## Resolver Registry
- registry runs with TLS and auth enabled
- canonical resolver definitions published and hashed; hashes match on-chain `resolver_hash`
- registry backups enabled and tested (snapshot + restore)

## Attester / zkTLS
- `REQUIRE_ZKTLS=1`; verify endpoint reachable and authenticated if required
- attester API auth token configured; rate limits set appropriately
- when `PROOF_FETCH_MODE=local`, `PROOF_STORE_DIR` is explicitly configured, already exists, resolves to a directory, and is not `/`
- local `file:` proof refs contain only relative paths under `PROOF_STORE_DIR`; arbitrary absolute paths, traversal/empty components, and symlink escapes are rejected
- local proof and public-input targets must be regular files; local reads are descriptor-bounded and do not follow symlink path components where the platform supports no-follow opens
- local reads are bounded by `PROOF_MAX_BYTES` (default 2,000,000 bytes) and `PUBLIC_INPUTS_MAX_BYTES` (default 256,000 bytes), with both pre-read size checks and a hard post-read cap
- proof store retention policy defined; audit log path writable and rotated

## Remote Signer
- auth required; allowlist enforced; TLS enabled when off-box
- signer audit logs writable and rotated
- health checks alerting wired to paging for 5xx / allowlist load failures

## Matching Keeper
- markets discovery mode configured (`program_scan` or explicit list)
- SQLite or backing store on durable disk with backups
- metrics/health endpoints scraped; alert on stalled match loop or backlog growth

## Monitoring and Alerting
- Prometheus scraping all services; Grafana dashboards linked to on-call
- `make ops-validate-alerts` passes against `ops/monitoring/prometheus.yml` and `ops/monitoring/alerts.yml`
- alerts for: attester 5xx/error rate, signer health, registry health, keeper websocket staleness, snapshot lag, backlog growth, Solana RPC errors, program errors in logs

## Backup / Restore
- program/IDL/types bundle archived
- resolver registry data backup tested
- signer allowlist and config backups stored
- `make ops-verify-restore` passes and exercises `make ops-backup` / `make ops-restore --force` on a staging copy

## Security Controls
- secrets stored in a secret manager; no keys in repo or CI artifacts
- API tokens rotated and scoped; least-privilege policy access for RPC/Vault/storage
- firewall rules/TLS in place for attester, registry, signer

## Runbook Readiness
- docs/operated_devnet.md and docs/ops_runbook.md steps rehearsed
- docs/signer_vault_ops.md steps rehearsed
- incident contacts, escalation paths, and rollback decision owners defined
