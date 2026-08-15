# Public devnet RC1 runbook

No mainnet command is authorized by this runbook. Substitute only dedicated
public-devnet secret-manager references; do not place values in this repository.

1. Verify the clean RC revision and toolchain, then run `cargo test --workspace --locked`, `anchor build`, `make demo`, and `bash scripts/check_zktls.sh`.
2. Record `solana genesis-hash`, artifact/IDL hashes, dedicated deploy authority public key, and generated program ID. Populate an out-of-repo rendered copy of `deploy/environments/public-devnet.json`.
3. Build and verify: `anchor build`; compare `shasum -a 256 target/deploy/prophet.so target/idl/prophet.json` against the release record.
4. Deploy with the dedicated authority through `python3 scripts/release.py deploy --environment public-devnet --release-tag v1.0.0-rc1` only after the release tool is configured for that environment. Verify program ID/upgrade authority with Solana CLI and explorer/RPC.
5. Render the operated stack into an out-of-repo directory, inject distinct public-devnet Vault Transit, registry, attester, keeper, RPC, monitoring, and rate-limit secrets/configuration; start services.
6. Initialize dedicated NotaryConfig and market authority. Publish reviewed Resolver V2 definitions bound to the recorded devnet genesis hash; configure primary and independent verifier IDs with required 2/2 agreement.
7. Execute the acceptance test below, then inspect market/vault/position/event state and confirm alert routing.

## Acceptance test

On devnet, capture JSON artifacts for market creation, YES/NO orders, match,
canonical evidence hash, both verifier results, 2/2 decision, threshold
signatures, settlement signature, redemption, and accounting reconciliation:

`initial collateral = payouts + protocol fees + legitimate remaining balances`.

Run a separate fault-injected verifier-YES/verifier-NO case. It passes only if
conflict state persists, settlement-signature count is zero, and no settlement
transaction exists. The deterministic local analogue is `make demo`; live
devnet acceptance must use the operated smoke path and retain receipts.

## Observability, recovery, and rollback

Inject verifier disagreement, stale evidence, signer/RPC/keeper/Vault failure,
and repeated settlement failure. Record metric, alert, severity, and operator
acknowledgement. Local configuration validation is insufficient evidence of
live alert delivery.

For rollback: halt automated submission, retain audit/evidence, rotate the
NotaryConfig version to invalidate pending signatures, deprecate affected
resolver definitions, then redeploy only a reviewed prior artifact with the
dedicated upgrade authority. Record RC version, prior version, artifact hashes,
program state, and verification commands. On-chain historical state cannot be
rolled back; unsafe state-changing rollback attempts are prohibited.
