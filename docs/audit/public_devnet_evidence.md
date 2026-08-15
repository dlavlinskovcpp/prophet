# Public devnet RC1 deployment evidence

Status: **BLOCKED BEFORE DEPLOYMENT**

Date checked: 2026-08-15. RC tag `v1.0.0-rc1` resolves to
`f3e2025b1d898c54e228810e000ae80516665904`.

## Completed preflight

- Toolchain observed: Anchor 1.0.1; Agave/Solana CLI 3.1.10; Rust 1.89.0;
  Node 20.19.6; Yarn 1.22.22.
- `cargo test --workspace --locked` and `anchor build` passed.
- Dedicated DEVNET-only bootstrap identities and the public devnet genesis hash
  are recorded in `deploy/environments/public-devnet.json`.

## Exact blockers

1. The deployment authority balance is `0 SOL`; devnet faucet requests were
   rate-limited. No deployment, registry, or test-transaction funding exists.
2. Bootstrap local keys are Git-ignored but have not been migrated to the
   required managed remote-signer/Vault boundary. No Vault Transit backend is
   provisioned.
3. No public-devnet resolver registry, attester, independent verifier pair,
   threshold-signer runtime, keeper, conflict/equivocation store, or monitoring
   alert route has been deployed and validated. Their configuration endpoints
   remain explicit placeholders.
4. Consequently there is no program deployment, ProgramData account, public
   transaction signature, live Resolver V2 evidence, 2/2 signer result,
   settlement, redemption, accounting reconciliation, conflict persistence, or
   live alert delivery to record.

No devnet transaction was submitted and no private key was exposed. The next
action is to fund the deployment identity through an approved devnet mechanism,
provision managed signing and operated services, validate the 2/2 policy and
monitoring, then run the live deployment runbook.
