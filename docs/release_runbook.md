# Release Runbook

This runbook covers the repo-supported release path for Prophet.

## Scope

The release flow now has three explicit stages:

- `plan`: generate a versioned release manifest from the current build artifacts
- `bundle`: archive the program binary, IDL, TS types, config, and manifest under `releases/`
- `deploy`: build, deploy, sync the IDL, verify the program, and archive the release bundle

The source of truth for environments is `deploy/environments/*.json`.

## Environments

Tracked environment configs:

- `deploy/environments/localnet.json`
- `deploy/environments/devnet.json`
- `deploy/environments/mainnet-beta.json`

Each config pins:

- cluster / RPC target
- wallet path
- program keypair path
- build artifact paths
- expected program id
- service endpoint metadata for the release manifest
- deployment manifests and env templates for the operated services

## Preconditions

Before any non-localnet release:

1. CI should be green.
2. `target/deploy/prophet.so`, `target/idl/prophet.json`, and `target/types/prophet.ts` must exist.
3. The git tree should be clean.
4. The wallet in the selected environment config must hold the upgrade authority and enough SOL for deployment.
5. The environment config's `expected_program_id` should match the actual program keypair and IDL address.
6. If you use the operated stack templates, render them first with `python3 scripts/render_operated_stack.py --environment <env>` so the tracked environment config carries the real public service endpoints.

## Commands

Plan a release:

```bash
python3 scripts/release.py plan --environment devnet --release-tag v0.2.3
```

Create a rollback bundle:

```bash
python3 scripts/release.py bundle --environment devnet --release-tag v0.2.3
```

Deploy and archive:

```bash
python3 scripts/release.py deploy --environment devnet --release-tag v0.2.3
```

Mainnet deploys require an explicit confirmation flag:

```bash
python3 scripts/release.py deploy --environment mainnet-beta --release-tag v0.2.3 --yes
```

Equivalent make targets:

- `make release-plan ENV=devnet TAG=v0.2.3`
- `make release-bundle ENV=devnet TAG=v0.2.3`
- `make release-deploy ENV=devnet TAG=v0.2.3`
- `make security-review-bundle ENV=devnet TAG=v0.2.3`

## What The Bundle Contains

Each release bundle is written to:

`releases/<TAG>/<ENV>/`

It includes:

- `manifest.json`
- `target/deploy/prophet.so`
- `target/idl/prophet.json`
- `target/types/prophet.ts`
- `target/deploy/prophet-keypair.json`
- environment config used for the release
- operated deployment templates referenced by the environment config
- the operated stack values template referenced by the environment config
- version source files (`Anchor.toml`, relevant `pyproject.toml`, `Cargo.toml`, `package.json`)

That bundle is the rollback artifact set.

## Review Package

Generate the external-review handoff package after the release artifacts are ready:

```bash
make security-review-bundle ENV=devnet TAG=v0.2.3
```

That writes `security-reviews/<TAG>/<ENV>/` with:

- a safe release snapshot for reviewers
- redacted configs
- sample resolver/proof/public-input fixtures
- invariant mapping
- findings and remediation trackers

## Post-Deploy Checks

After deploy:

1. Confirm `solana program show` succeeds for the deployed program.
2. Confirm the bundled `manifest.json` has the expected tag, environment, program id, and hashes.
3. Update downstream runtime config:
   - `PROPHET_PROGRAM_ID`
   - attester / SDK / keeper RPC endpoints if they changed
4. Run the environment-specific smoke path before traffic cutover.

## Rollback

Rollback means redeploying the previous archived program binary and re-syncing its matching IDL.

Use the previous bundle, for example:

`releases/v0.2.2/devnet/`

Rollback procedure:

1. Identify the last known good bundle.
2. Redeploy its `target/deploy/prophet.so` with the same upgrade-authority wallet and program id.
3. Re-apply its `target/idl/prophet.json`.
4. Revert runtime config and operators to the previous release's manifest if any addresses or endpoints changed.
5. Re-run post-deploy checks.

This repo does not automate rollback execution because that is a destructive production action. The bundle is what makes rollback deterministic.

## CI Role

CI validates the release path by generating release bundles from the built artifacts and uploading them as workflow artifacts. Because the CI localnet flow deploys a throwaway test program id, the workflow rewrites `expected_program_id` in temporary copied environment configs before running `scripts/release.py`. Real release configs under `deploy/environments/` remain the source of truth for operator-driven releases.
