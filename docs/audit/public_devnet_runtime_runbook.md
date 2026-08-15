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

## Current implementation gate

The repository currently lacks standalone HTTP service entrypoints for verifier
one, verifier two, and the signer-policy/conflict coordinator. The infrastructure
template therefore cannot pass preflight or be declared operational until those
existing modules are exposed as independently deployable services with durable
state and health endpoints. Do not replace them with duplicate verification
logic merely to make the stack appear healthy.
