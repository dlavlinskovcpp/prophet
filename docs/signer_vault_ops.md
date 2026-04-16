# Signer / Vault Operations

This runbook covers the production remote-signer path when Prophet is operated with HashiCorp Vault Transit:

- Vault Transit bootstrap for Ed25519 notary keys
- backend and service dry-run signing checks
- signer allowlist rotation
- compromised or retired notary key handling

The bundled production path is `REMOTE_SIGNER_BACKEND=command` with `python /app/scripts/vault_transit_signer.py` as the command wrapper. The remote-signer service boundary does not change: the attester still calls the auth-protected `/sign` endpoint, while the remote signer delegates the actual Ed25519 signing operation to Vault Transit.

The repo-side helpers are:

- `make signer-vault-bootstrap`
- `make signer-dry-run`
- `make signer-allowlist`

AWS KMS remains supported in code through `REMOTE_SIGNER_BACKEND=aws_kms`, but the operated manifests and release path are now Vault-first.

## 1. Bootstrap Vault Transit Keys

For Solana notary keys, use non-derived `ed25519` Transit keys so the exported public key stays stable and the wrapper can map each requested notary pubkey to one Transit key name.

Create the keys in Vault Transit if they do not already exist:

```bash
make signer-vault-bootstrap ARGS="\
  --vault-addr https://vault.devnet.example \
  --token-file /etc/prophet/devnet/remote-signer/vault-token \
  --cacert /etc/prophet/devnet/remote-signer/vault-ca.pem \
  --create-missing \
  --key-name prophet-devnet-notary-01 \
  --key-name prophet-devnet-notary-02 \
  --output-allowlist /etc/prophet/devnet/signer_allowlist.txt \
  --output-key-map /etc/prophet/devnet/remote-signer/vault-transit-key-map.json"
```

The output includes:

- each Transit key name and its derived Solana pubkey
- `command_public_keys_csv`, which is what you copy into `REMOTE_SIGNER_COMMAND_PUBLIC_KEYS`
- a normalized allowlist file for `REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH`
- a `vault-transit-key-map.json` file that maps Solana pubkeys to Transit key names

The operated compose templates mount `${PROPHET_SECRET_ROOT}/remote-signer/` into `/app/remote-signer-secrets`, so place the Vault token, CA bundle, and key-map file there before starting the signer.

## 2. Configure The Remote Signer

Set the production remote-signer env to use the Vault wrapper and the file-backed allowlist:

```dotenv
REMOTE_SIGNER_BACKEND=command
REMOTE_SIGNER_COMMAND=python /app/scripts/vault_transit_signer.py
REMOTE_SIGNER_COMMAND_PUBLIC_KEYS=<pubkey-1>,<pubkey-2>
REMOTE_SIGNER_REQUIRE_ALLOWLIST=1
REMOTE_SIGNER_ALLOWLIST_MODE=file
REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH=/app/signer_allowlist.txt

VAULT_ADDR=https://vault.devnet.example
VAULT_TOKEN_FILE=/app/remote-signer-secrets/vault-token
VAULT_CACERT=/app/remote-signer-secrets/vault-ca.pem
VAULT_TRANSIT_MOUNT=transit
VAULT_TRANSIT_KEY_MAP_PATH=/app/remote-signer-secrets/vault-transit-key-map.json
VAULT_TRANSIT_TIMEOUT_S=5
```

If the signer serves exactly one notary key, you can use `VAULT_TRANSIT_KEY_NAME=<name>` instead of a key-map file, but the key map is the safer default for threshold sets because it makes the requested pubkey-to-key-name mapping explicit and auditable.

## 3. Dry-Run Signing Checks

Run both checks before shipping a release or rotating signer keys.

### Backend Dry Run

This validates Vault reachability, key mapping, and allowlist membership directly on the signer host:

```bash
make signer-dry-run ARGS="backend"
```

The check fails if:

- Vault auth or TLS is misconfigured
- the key-map file is missing or stale
- the allowlist file is missing or stale
- the requested pubkey is not allowlisted
- Vault returns an invalid signature payload

### Service Dry Run

This validates the auth-protected HTTP path that the attester uses:

```bash
make signer-dry-run ARGS="\
  --public-key <notary-pubkey> \
  service \
  --url https://signer.devnet.example/sign \
  --api-key <remote-signer-api-key>"
```

The script fetches `/health`, then calls `/sign`, and prints a JSON result with signer health plus signature metadata.

## 4. Allowlist Rotation Workflow

When adding or retiring notary keys, rotate in this order.

1. Bootstrap the candidate Vault Transit keys and generate staged allowlist/key-map artifacts.
2. Add the new pubkeys to the live signer allowlist before updating on-chain config:

```bash
make signer-allowlist ARGS="\
  --path /etc/prophet/devnet/signer_allowlist.txt \
  add \
  --pubkeys-file /tmp/prophet-devnet.allowlist"
```

3. Copy the refreshed `vault-transit-key-map.json` to the signer secret mount if new key names were added.
4. Run backend and service dry-runs for every new pubkey.
5. Update the on-chain `NotaryConfig` with `ProphetClient.update_notary_config(...)`.
6. After the new config is active and dry-runs still pass, remove retired keys from the allowlist:

```bash
make signer-allowlist ARGS="\
  --path /etc/prophet/devnet/signer_allowlist.txt \
  remove \
  --public-key <retired-pubkey>"
```

Inspect the current normalized file at any time with:

```bash
make signer-allowlist ARGS="--path /etc/prophet/devnet/signer_allowlist.txt show"
```

The allowlist tool writes updates atomically, so the running service will pick them up on the next refresh without partial files. The Vault key-map file is also written atomically by `make signer-vault-bootstrap`.

## 5. Compromised Or Retired Key Handling

If a notary key is compromised:

1. Remove it from the remote-signer allowlist immediately.
2. Revoke the remote signer token or policy access to the compromised Transit key name.
3. Update the on-chain `NotaryConfig` to remove the compromised signer and adjust the threshold set as needed.
4. Re-run backend and service dry-runs against the surviving signer set.
5. Re-resolve any stuck markets with fresh signatures from the new config version.

If a key is only being retired, use the staged rotation flow instead of immediate removal.

Important on-chain behavior: `resolve_market_threshold` binds the signed message to the current `NotaryConfig.version`. Updating `NotaryConfig` invalidates signatures from the prior version, including for unresolved markets that still point at the same config account. That is what makes emergency signer removal effective, but it also means old signatures must be re-collected after a config change.

## 6. Release Gate

Before a production release:

- archive the JSON output from `make signer-vault-bootstrap` for the release record
- confirm `REMOTE_SIGNER_COMMAND_PUBLIC_KEYS` matches the current staged signer set
- run `make signer-dry-run ARGS="backend"`
- run `make signer-dry-run ARGS="--public-key <pubkey> service --url <https signer url> --api-key <token>"`
- confirm `/health` reports `ok: true`, `allowlist_ready: true`, and the expected loaded pubkeys
