# Public-devnet provisioning evidence

Status: **PARTIALLY PROVISIONED — DEPLOYMENT BLOCKED**

This record is a no-broadcast infrastructure preflight. No program deployment,
market transaction, settlement transaction, or mainnet action was performed.

## Release and cluster facts

| Item | Value |
| --- | --- |
| RC1 tag | `v1.0.0-rc1` |
| RC1 commit | `f3e2025b1d898c54e228810e000ae80516665904` |
| RPC endpoint | `https://api.devnet.solana.com` |
| WebSocket endpoint | `wss://api.devnet.solana.com` |
| Observed devnet genesis hash | `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG` |
| Intended program ID (not deployed) | `3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE` |

## Public identities

| Role | Public address or identity |
| --- | --- |
| Deployment authority | `9ZmpShfzkrdCEhkSe8Hq7FN45uCQm2Uo1X9T834LsNBw` |
| Program keypair | `3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE` |
| Resolver registry authority | `EQpSbrV85kdbRLQsM7zFHcRELkk8dZK7HAkobZqfKBuC` |
| Threshold signer #1 | `FWq7715Lzdzn3ofYr5HHVSNh1dLAmkiFxNpfUTh2h3vf` |
| Threshold signer #2 | `4mrX5LqBtoRWapJT6bijDkpThCoYNcDmQkcfXchWhE14` |
| Keeper authority | `5sL3Z89NdNVYfCTrmnjzCcGHAtjHVJwodDyZswv1P19F` |
| Verifier #1 | `prophet.verifier.pyth.primary@2.0.0` (runtime not provisioned) |
| Verifier #2 | `prophet.verifier.pyth.independent@2.0.0` (runtime not provisioned) |

## Completed checks

- The six DEVNET-only key files exist beneath an ignored local `private/`
  directory; `git check-ignore` confirmed the directory is excluded from Git.
- The resolved public identities, expected program ID, devnet RPC/WebSocket URL,
  and observed genesis hash are recorded in
  `deploy/environments/public-devnet.json`. Its JSON structure validates.
- Each bootstrap keypair's derived public key matches its configured public
  identifier. This verifies local bootstrap continuity only; it is not evidence
  of a managed-signer migration.
- A direct cluster query returned the recorded devnet genesis hash.
- A direct devnet balance query returned **7.5 SOL** for the dedicated
  deployment authority, satisfying the 6.25 SOL funding target.
- Toolchain checks matched Anchor 1.0.1, Agave/Solana CLI 3.1.10, Rust 1.89.0,
  Node 20.19.6, and Yarn 1.22.22. `cargo test --workspace --locked` and
  `anchor build` passed during the preflight.

## Secret handling

Only key **locations by type** are recorded: bootstrap DEVNET-only identities
are local and Git-ignored; the required remote signer/Vault Transit and service
credentials have not been provisioned. No raw secret, token, or seed phrase is
present in this repository or this document.

## Funding calculation (public devnet, 2026-08-15)

The calculation uses the pinned `target/deploy/prophet.so` size of 438,264
bytes and rent-exemption values queried from the configured devnet RPC. It does
not assume a resolver-registry on-chain account: Resolver V2 registry
initialization is an off-chain service operation in this release.

| Allocation | Bytes | Devnet rent-exempt minimum (SOL) |
| --- | ---: | ---: |
| Deploy staging buffer (`ELF + 37` bytes) | 438,301 | 3.05146584 |
| ProgramData (`ELF + 45` bytes) | 438,309 | 3.05152152 |
| Upgradeable program account | 36 | 0.00114144 |
| 2/2 NotaryConfig (`8 + 1,072`) | 1,080 | 0.00840768 |
| Test quote mint | 82 | 0.00146160 |
| One Market (`8 + 384`) | 392 | 0.00361920 |
| Market vault plus two trader token accounts | 3 × 165 | 0.00611784 |
| Two orders | 2 × 136 | 0.00367488 |
| Two positions | 2 × 136 | 0.00367488 |
| **Mandatory rent at deployment peak** | — | **6.13108488** |

The upgradeable-loader buffer and ProgramData allocations coexist during the
initial deployment; the buffer is therefore included in the peak requirement.
The lifecycle allocations describe one market, two traders, two orders, and
the associated resolution/redeem path. The deployment authority's observed
balance is **7.5 SOL** as of the current preflight.

The required funding target is **6.25 SOL** to
`9ZmpShfzkrdCEhkSe8Hq7FN45uCQm2Uo1X9T834LsNBw`. It consists of the exact
6.13108488 SOL mandatory-rent amount plus a fixed 0.11891512 SOL transaction
fee and operational-safety reserve. No priority fee is configured. The reserve
must be rechecked against the RPC fee schedule immediately before broadcast;
it is not represented as account rent.

The funding target is satisfied with 1.25 SOL remaining above it. Earlier
public-faucet requests were rate-limited; no real SOL or mainnet mechanism was
used.

## Managed signer boundary assessment

The supported threshold-signing integration is the Vault Transit command
backend documented in `docs/signer_vault_ops.md`. It creates non-exportable
Ed25519 Transit keys and maps their derived Solana public keys through the
remote-signers allowlist. No reachable Vault endpoint, Vault token, or managed
signer backend is configured in this environment, so no key migration or
identity-continuity assertion can be performed.

This has an important consequence: the bootstrap signer private keys cannot be
imported into Transit while retaining their public keys. A compliant migration
must create two new non-exportable Transit keys, record only their derived
public keys and backend key identifiers, and replace the bootstrap signer
public keys in the devnet 2/2 policy before any market is initialized. The
current bootstrap signer identities must not be represented as managed keys.

The existing release helper also requires local filesystem paths for
`wallet_path` and `program_keypair_path`, and invokes Anchor with a local
provider wallet. It has no Vault Transit signer adapter. Therefore Vault Transit
cannot currently back the deployment authority or program keypair through the
repository's deployment tooling. The safest supported interim choice for those
roles is a dedicated, permission-restricted, Git-ignored DEVNET-only keypair
used only from an encrypted release host; it does not satisfy the managed-key
release gate. Resolver-registry authorization is service authentication in the
current design rather than a Solana signer integration, so it likewise has no
supported Vault migration path at this phase.

## Remaining blocking conditions

1. Provision a managed Vault Transit/remote-signer backend, create two new
   independent Transit keys, update the devnet 2/2 signer policy to their
   derived public identities, and successfully run the backend identity/dry-run
   checks. Existing bootstrap signer identities cannot be migrated unchanged.
2. The attester, two independent verifier runtimes, signer-policy engine,
   conflict/equivocation persistence, and keeper are not provisioned. The
   service endpoint fields consequently remain explicit configuration
   placeholders.
3. Monitoring, alert routing, and an alert-delivery test are not provisioned.
4. An end-to-end dry run cannot yet validate managed signer public keys,
   resolver-registry configuration, service cluster binding, or the 2/2 policy
   against live runtimes.

## Runtime foundation

A safe single-host public-devnet foundation is available under
`deploy/operated/public-devnet/`: persistent non-dev Vault configuration,
private Compose network, mounted secret paths, Prometheus, Alertmanager, and
Grafana without anonymous access. Its preflight validates the RPC genesis,
configured program ID, distinct managed signer identities, signer policy
version, and alert-receiver declaration without submitting a transaction.

It remains intentionally blocked: no Vault instance or operator credentials
exist, no managed Transit keys have been created, and verifier/policy modules
do not yet expose the independent runtime service entrypoints required by the
deployment brief. No placeholder service is treated as a verifier.

These conditions must be closed before any public-devnet deployment attempt.
