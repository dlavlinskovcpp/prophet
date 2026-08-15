# Public testnet/devnet deployment plan

This document authorizes preparation only. It does **not** authorize mainnet
deployment. Use a dedicated cluster (`devnet` or a named public testnet) with
an explicit genesis hash recorded in resolver definitions and signer policy.

## Preconditions

- Create dedicated offline-controlled upgrade authority, market authority,
  registry operator, and threshold signer identities. Do not reuse developer,
  CI, fixture, or demo keys.
- Render a separate operated stack from `deploy/operated/devnet/`; populate
  secret manager references outside Git, and set distinct resolver-registry,
  attester, signer, keeper, RPC, rate-limit, and monitoring values.
- Create a testnet registry namespace and publish only reviewed resolver
  definitions whose feed/source/cluster bindings match that network.
- Record program ID, artifact digest, IDL hash, git revision, config hashes,
  cluster genesis hash, and notary-config version in the release record.

## Commands

Run only from a hardened release workstation after filling environment-specific
paths and public keys:

```sh
anchor --version                    # must be anchor-cli 1.0.1
solana --version                    # must be 3.1.10
python3 scripts/release.py plan --environment devnet --release-tag <tag>
python3 scripts/release.py bundle --environment devnet --release-tag <tag>
python3 scripts/release.py deploy --environment devnet --release-tag <tag>
python3 scripts/render_operated_stack.py --environment devnet --output-dir <outside-repo-dir>
python3 scripts/seed_resolver.py <reviewed-resolver.json> --registry-url <testnet-registry-url>
```

After deployment, verify program/IDL hashes, initialize a dedicated testnet
notary configuration, run `make operated-smoke` with explicit `RPC_URL` and
`PROPHET_PROGRAM_ID`, execute the agent demo, and confirm alert delivery.

## Rollback

Stop attester/keeper submission first; preserve audit logs and evidence. If an
artifact rollback is approved, use only the dedicated upgrade authority and a
previously reviewed program artifact through `scripts/release.py deploy`.
Rotate or update the notary configuration to invalidate pending signatures,
deprecate affected resolver entries without mutating definitions, and publish
an incident notice. Never roll back by deleting state or reusing compromised
keys. See `docs/release_runbook.md` and `docs/ops_runbook.md`.
