# Release Runbook

This runbook covers the repo-supported release path for Prophet.

## Scope

The release flow now has three explicit stages:

- `plan`: generate a versioned release manifest from the current build artifacts and public deployment identity
- `bundle`: archive the program binary, IDL, TS types, sanitized public environment snapshot, and manifest under `releases/`
- `deploy`: build, deploy with operator-provisioned credentials, sync the IDL, verify the program, and archive the release bundle

The source of truth for environments is `deploy/environments/*.json`. Deployment credential fields in those source configs are deployment inputs only; they are not release artifacts.

## Environments

Tracked environment configs:

- `deploy/environments/localnet.json`
- `deploy/environments/devnet.json`
- `deploy/environments/mainnet-beta.json`

Each config pins:

- cluster / RPC target
- external deployment credential inputs such as wallet or program-keypair paths/references
- build artifact paths
- expected public program id
- service endpoint metadata for the release manifest
- deployment manifests and env templates for the operated services

The bundle/plan path resolves the program identity from public sources (`expected_program_id` and the IDL address). It does not need to read the program private keypair merely to identify the program.

## Preconditions

Before any non-localnet release:

1. CI should be green.
2. `target/deploy/prophet.so`, `target/idl/prophet.json`, and `target/types/prophet.ts` must exist.
3. The git tree should be clean.
4. For an actual deploy or rollback, the operator must provision the upgrade/deployment authority credential outside the release bundle and ensure it has enough SOL where applicable.
5. The environment config's `expected_program_id` should match the IDL address and, at deployment execution time, the externally supplied program identity.
6. If you use the operated stack templates, render them first with `python3 scripts/render_operated_stack.py --environment <env>` so the tracked environment config carries the real public service endpoints.

A pure `plan` or `bundle` operation must not require the deployment wallet, program keypair, fee payer, or a resolved secret-manager credential to exist.

For non-localnet releases, release validation now treats the secure settlement topology as mandatory release metadata. The environment must name distinct verifier A/B endpoints and identities, a durable coordinator database, durable SigningJournal and submission-journal paths, strict 2/2 signer identities, and `resolution_mode=secure-coordinator`. Direct attester settlement and the generic remote signer settlement path must both be disabled.

`scripts/render_operated_stack.py` follows the same boundary for production-shaped devnet/mainnet configuration. It renders only resolver-registry and matching-keeper env files; verifier A/B, coordinator, secure-settlement, their internal bearer tokens, and the two Vault signer credentials are provisioned separately through the operator secret/configuration boundary. The renderer rejects legacy `ATTESTER_BASE_URL` / `REMOTE_SIGNER_*` settlement values rather than silently reintroducing them into release metadata.

## Commands

Plan a release:

```bash
python3 scripts/release.py plan --environment devnet --release-tag <release-tag>
```

Create a rollback bundle:

```bash
python3 scripts/release.py bundle --environment devnet --release-tag <release-tag>
```

Deploy and archive:

```bash
python3 scripts/release.py deploy --environment devnet --release-tag <release-tag>
```

Mainnet deploys require an explicit confirmation flag:

```bash
python3 scripts/release.py deploy --environment mainnet-beta --release-tag <release-tag> --yes
```

Equivalent make targets:

- `make release-plan ENV=devnet TAG=<release-tag>`
- `make release-bundle ENV=devnet TAG=<release-tag>`
- `make release-deploy ENV=devnet TAG=<release-tag>`
- `make security-review-bundle ENV=devnet TAG=<release-tag>`

## What The Bundle Contains

Each release bundle is written to:

`releases/<TAG>/<ENV>/`

It includes:

- `manifest.json` with the public program id, release metadata, and artifact hashes
- `target/deploy/prophet.so`
- `target/idl/prophet.json`
- `target/types/prophet.ts`
- a sanitized public snapshot of the environment config
- operated deployment templates referenced by the environment config
- the operated stack values template referenced by the environment config
- version source files (`Anchor.toml`, relevant `pyproject.toml`, `Cargo.toml`, `package.json`)

Release and rollback bundles do **not** contain the program private keypair, deployment/upgrade-authority wallet, fee-payer keypair, seed material, wallet secrets, or secret-manager-resolved deployment credentials. Secret/keypair filesystem paths and external secret-manager references are omitted from the bundled environment snapshot and release manifest.

The release tool also rejects a generated bundle if it contains a private-key-shaped filename or a JSON value shaped like a 64-byte Solana secret-key array, including a small renamed JSON payload.

The bundle is the rollback artifact set for public/artifact state. It is safe to place in normal artifact storage **with respect to Solana deployment private-key material**. This is not a blanket claim that every bundled configuration or operational metadata field is non-sensitive.

## Review Package

Generate the external-review handoff package after the release artifacts are ready:

```bash
make security-review-bundle ENV=devnet TAG=<release-tag>
```

That writes `security-reviews/<TAG>/<ENV>/` with:

- a release snapshot that uses the same public-only credential boundary
- redacted configs
- sample resolver/proof/public-input fixtures
- invariant mapping
- findings and remediation trackers

## Post-Deploy Checks

After deploy:

1. Confirm `solana program show` succeeds for the deployed program.
2. Confirm the bundled `manifest.json` has the expected tag, environment, public program id, and hashes, and no deployment credential paths.
3. Update downstream runtime config:
   - `PROPHET_PROGRAM_ID`
   - attester / SDK / keeper RPC endpoints if they changed
4. Run the environment-specific smoke path before traffic cutover.

## Rollback

Rollback means redeploying the previous archived program binary and re-syncing its matching IDL.

Use the previous bundle, for example:

`releases/v0.2.2/devnet/`

Rollback procedure:

1. Identify the last known good bundle and verify its binary/IDL hashes and target program id from `manifest.json`.
2. Separately obtain the authorized deployment/upgrade credential from the operator's secure wallet or secret-management boundary. The bundle intentionally does not provide this credential.
3. Redeploy the bundle's `target/deploy/prophet.so` to the manifest's program id using that external authorized credential.
4. Re-apply the bundle's `target/idl/prophet.json`.
5. Revert runtime config and operators to the previous release's manifest if any public addresses or endpoints changed.
6. Re-run post-deploy checks.

This repo does not automate rollback execution because that is a destructive production action. The bundle makes the artifact selection deterministic; credential acquisition remains an explicit operator responsibility outside the artifact boundary.

## CI Role

CI validates the release path by generating release bundles from the built artifacts and uploading them as workflow artifacts. The CI localnet flow may create and use a throwaway program keypair to build/deploy a temporary test program. The bundle stage reads the resulting public program id from the built IDL, rewrites only `expected_program_id` in temporary copied environment configs, and does not read the throwaway private keypair to identify the program. The resulting bundle excludes the throwaway keypair and is checked by the same bundle secret guard. Real release configs under `deploy/environments/` remain the source of truth for operator-driven releases.
