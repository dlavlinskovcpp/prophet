# Public-devnet runtime runbook

This is a single-host, production-shaped **devnet** stack. It must not be used
for mainnet. It does not deploy the Prophet program or submit market
transactions.

## Host and network

Use a dedicated Linux host with Docker Compose v2, 4 vCPU, 8 GB RAM, 80 GB
persistent disk, and outbound access only to Solana devnet and approved oracle
providers. Do not publish Vault, Prometheus, Alertmanager, Grafana, registry,
or remote-signer ports directly. Put any public API behind a separately managed
TLS reverse proxy with authentication and an allowlist.

## Bootstrap

1. Check out the tagged RC and create `/etc/prophet/public-devnet` (mode 0700)
   and `/var/lib/prophet/public-devnet` (owned by the service operator).
   Before starting Compose, create the writable runtime directories
   `resolver_store`, `resolver_audit`, `coordinator`, `signing`, `submission`,
   and `matching-keeper` with owner/group `10001:10001`. The fee-payer and
   keeper key files remain outside that tree under the secret root: on Linux,
   set each file to `root:10001`, mode `0440`, and protect every parent
   directory from untrusted traversal. Docker Desktop operators must use an
   equivalent managed secret-volume mechanism that preserves read access for
   UID/GID 10001 without making either key world-readable.
2. Copy `deploy/operated/public-devnet/runtime.env.example` outside the
   repository, set only devnet values, then set mode 0600. Populate actual
   managed signer public keys and policy version only after Transit bootstrap.
3. Copy `vault.hcl.example` to the secret root. Mount a CA-signed TLS
   certificate/key in `vault/tls`; do not use `vault server -dev`.
4. Initialize and unseal Vault interactively using an operator-controlled
   procedure. Store recovery/unseal material in an approved secret manager,
   never this repository. Enable a file or socket audit device writing beneath
   the persistent audit mount, then enable `transit`.
5. Create non-exportable `ed25519` Transit keys `prophet-devnet-signer-a` and
   `prophet-devnet-signer-b`. Run the existing `make signer-vault-bootstrap`
   from the secured operator host to produce the allowlist and public-key map.
   Preserve its public-only output with the release evidence.
6. Explicitly rotate the off-chain devnet 2/2 signer policy to the two derived
   public keys, increment its version, bind it to the devnet genesis hash, and
   remove bootstrap keys from its allowlist. Do not permit fallback.

## Start, validate, recover

Run `make devnet-runtime-preflight` before every start, then
`make devnet-runtime-up`. `make devnet-runtime-down` deliberately omits volume
deletion, preserving Vault, audit, Prometheus, Grafana, and conflict data.
Use `make devnet-runtime-status` and `make devnet-runtime-logs` for diagnosis.

Configure Alertmanager from a secret-mounted configuration with at least one
real receiver, send a test alert, and archive confirmation outside Git. Back up
the runtime root, Vault storage, audit records, conflict/equivocation store, and
the managed signer public-key map before an upgrade. Re-run preflight after
restart or upgrade.

## Container sandbox boundary

The public-devnet Compose profile runs Prophet application services as
`10001:10001` with a read-only root filesystem, all Linux capabilities dropped,
`no-new-privileges`, a 256-process ceiling, and a 64 MiB `/tmp` tmpfs. Durable
SQLite/WAL and audit data are restricted to explicit mounts. The control network
is internal; only verifier A/B, secure settlement, the keeper, and alerting have
the egress membership their current roles require. No Prophet application port
is host-published. These settings do not replace the remaining real-infrastructure
and live-lifecycle gates below.

## RC4.3 P0C2 operated sandbox acceptance

Before the first Prophet program or public-market deployment, record a passing
**RC4.3 P0C2 OPERATED SANDBOX ACCEPTANCE** exercise against the provisioned
public-devnet runtime. It must demonstrate all of the following:

1. Managed Vault Transit signer A and signer B are healthy.
2. Independent verifier A/B runtime configurations are installed.
3. A disposable devnet fee-payer secret is mounted with the documented
   `root:10001`, `0440` Linux permission contract.
4. The selected devnet RPC is reachable.
5. Every Prophet application container has the P0C2 sandbox controls active.
6. A strict 2/2 secure-settlement lifecycle completes.
7. Coordinator, signing, and submission SQLite/WAL state survives restart.
8. The signer-B rotation exercise remains successful.
9. Secure settlement can read but cannot modify the fee-payer secret.
10. Unrelated containers cannot access that secret.
11. Application containers report `CapEff=0` and `NoNewPrivs=1`.
12. Writes to the root filesystem fail while `/tmp` and designated durable
    mounts remain usable.

This is a deployment acceptance gate, not authorization to deploy now. It
remains deferred until the planned public-devnet Vault, signer, verifier,
fee-payer, and RPC infrastructure is available.

## Current implementation gate

The repository currently lacks standalone HTTP service entrypoints for verifier
one, verifier two, and the signer-policy/conflict coordinator. The infrastructure
template therefore cannot pass preflight or be declared operational until those
existing modules are exposed as independently deployable services with durable
state and health endpoints. Do not replace them with duplicate verification
logic merely to make the stack appear healthy.
