# Signer / KMS Operations

This runbook covers the production remote-signer path:

- AWS KMS bootstrap for Ed25519 notary keys
- backend and service dry-run signing checks
- signer allowlist rotation
- compromised or retired notary key handling

The repo-side helpers are:

- `make signer-kms-bootstrap`
- `make signer-dry-run`
- `make signer-allowlist`

All three wrap scripts in `apps/oracle-attester/scripts/`.

## 1. Bootstrap AWS KMS Keys

Create customer-managed Ed25519 signing keys in AWS KMS. A typical flow is:

```bash
aws kms create-key \
  --region us-east-1 \
  --key-spec ECC_NIST_EDWARDS25519 \
  --key-usage SIGN_VERIFY \
  --description "Prophet devnet notary 01"

aws kms create-alias \
  --region us-east-1 \
  --alias-name alias/prophet-devnet-notary-01 \
  --target-key-id <kms-key-id>
```

Attach least-privilege IAM for the remote signer host or task role. The runtime only needs:

- `kms:GetPublicKey`
- `kms:Sign`

Then resolve the Solana notary pubkeys from KMS and write the allowlist file:

```bash
make signer-kms-bootstrap ARGS="\
  --region us-east-1 \
  --key-id alias/prophet-devnet-notary-01 \
  --key-id alias/prophet-devnet-notary-02 \
  --output-allowlist /tmp/prophet-devnet.allowlist"
```

The output includes:

- configured KMS key ids and resolved ARNs
- derived Solana pubkeys
- the normalized allowlist entries to copy into `REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH`

For the operated compose templates, that file is mounted from `PROPHET_SECRET_ROOT/<environment>/signer_allowlist.txt`.

## 2. Configure The Remote Signer

Set the production remote signer env to use KMS and the file-backed allowlist:

```dotenv
REMOTE_SIGNER_BACKEND=aws_kms
REMOTE_SIGNER_AWS_KMS_REGION=us-east-1
REMOTE_SIGNER_AWS_KMS_KEY_IDS=alias/prophet-devnet-notary-01,alias/prophet-devnet-notary-02
REMOTE_SIGNER_REQUIRE_ALLOWLIST=1
REMOTE_SIGNER_ALLOWLIST_MODE=file
REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH=/app/signer_allowlist.txt
```

Before bringing the service up, copy the rendered allowlist into the secret mount used by the environment.

## 3. Dry-Run Signing Checks

Run both checks before shipping a release or rotating signer keys.

### Backend Dry Run

This validates direct KMS reachability, key shape, and allowlist membership from the signer host:

```bash
make signer-dry-run ARGS="backend"
```

For command-backed signers, pass the exact pubkey to test:

```bash
make signer-dry-run ARGS="--public-key <notary-pubkey> backend"
```

The check fails if:

- KMS key discovery fails
- the allowlist file is missing or stale
- the requested pubkey is not allowlisted
- the backend returns an invalid signature payload

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

1. Bootstrap the candidate KMS keys and generate a staged allowlist file.
2. Add the new pubkeys to the live signer allowlist before updating on-chain config:

```bash
make signer-allowlist ARGS="\
  --path /etc/prophet/devnet/signer_allowlist.txt \
  add \
  --pubkeys-file /tmp/prophet-devnet.allowlist"
```

3. Run backend and service dry-runs for every new pubkey.
4. Update the on-chain `NotaryConfig` with `ProphetClient.update_notary_config(...)`.
5. After the new config is active and dry-runs still pass, remove retired keys from the allowlist:

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

The allowlist tool writes updates atomically, so the running service will pick them up on the next refresh without rewriting partial files.

## 5. Compromised Or Retired Key Handling

If a notary key is compromised:

1. Remove it from the remote signer allowlist immediately.
2. Disable its KMS signing path or revoke the signer host's IAM access to that key.
3. Update the on-chain `NotaryConfig` to remove the compromised signer and bump the threshold set as needed.
4. Run the backend and service dry-runs against the remaining signer set.
5. Re-resolve any stuck markets with fresh signatures from the new config version.

If a key is only being retired, use the staged rotation flow instead of immediate removal.

Important on-chain behavior: `resolve_market_threshold` binds the signed message to the current `NotaryConfig.version`. Updating `NotaryConfig` invalidates signatures from the prior version, including for unresolved markets that still point at the same config account. That is what makes emergency signer removal effective, but it also means old signatures must be re-collected after a config change.

## 6. Release Gate

Before a production release:

- save the JSON output from `make signer-kms-bootstrap` for the release record
- run `make signer-dry-run ARGS="backend"`
- run `make signer-dry-run ARGS="--public-key <pubkey> service --url <https signer url> --api-key <token>"`
- confirm `/health` reports `ok: true`, `allowlist_ready: true`, and the expected KMS-backed pubkeys
