# Public-devnet infrastructure inventory

Status: **partially provisioned — not ready for deployment**. This inventory
records public identifiers and secret-handling procedures only. It never
contains key material, seed phrases, tokens, or credentials.

Funding status: the dedicated deployment authority has **7.5 devnet SOL** as
verified on 2026-08-15, exceeding the documented 6.25 SOL deployment target.

## Secret-storage model

The initial DEVNET-only key material is stored in a local `private/` directory
outside version control, protected by filesystem permissions and a Git ignore
rule. This is acceptable only for bootstrap validation. Before a public-devnet
deployment, deployment and threshold-signing keys must move to an approved
remote signer / Vault Transit or encrypted OS-keychain deployment environment.
No key is permitted in a committed `.env` file.

| Component | Purpose and public identifier | Secret storage and permitted access | Rotation and compromise response |
| --- | --- | --- | --- |
| Deployment authority | Upgrade/deployment authorization. `9ZmpShfzkrdCEhkSe8Hq7FN45uCQm2Uo1X9T834LsNBw` | Bootstrap: local ignored DEVNET-only key; release operator only. Required before deployment: approved remote/managed secret store. | Create replacement authority in the managed store; transfer upgrade authority only through an authorized devnet change. If compromised, stop deployments and rotate immediately. |
| Prophet program keypair | Future devnet program address. `3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE` | Bootstrap: local ignored DEVNET-only key; release operator only. | A deployed program address cannot be silently replaced; if compromised before deployment, generate a new key and update the public configuration. |
| Resolver registry authority | Authorizes devnet Resolver V2 registry operations. `EQpSbrV85kdbRLQsM7zFHcRELkk8dZK7HAkobZqfKBuC` | Bootstrap: local ignored DEVNET-only key; release operator only. Required: managed signer. | Disable affected runtime actions, establish replacement authority under the governed devnet procedure, and audit registry changes. |
| Verifier #1 | Independent verifier identity: `prophet.verifier.pyth.primary@2.0.0`. Public signing identity is not provisioned. | Runtime secret store not provisioned; verifier service has no access grant. | Version and identity rotation must be explicit in Resolver V2 policy; quarantine on compromise. |
| Verifier #2 | Independent verifier identity: `prophet.verifier.pyth.independent@2.0.0`. Public signing identity is not provisioned. | Runtime secret store not provisioned; verifier service has no access grant. | Version and identity rotation must be explicit in Resolver V2 policy; quarantine on compromise. |
| Threshold signer #1 | Bootstrap first member of the required 2/2 policy. `FWq7715Lzdzn3ofYr5HHVSNh1dLAmkiFxNpfUTh2h3vf` | Local ignored DEVNET-only key; it is **not** a managed signer. A new non-exportable Transit identity is required. | Add the new managed pubkey through explicit policy versioning, validate it, then retire this bootstrap identity. |
| Threshold signer #2 | Bootstrap second member of the required 2/2 policy. `4mrX5LqBtoRWapJT6bijDkpThCoYNcDmQkcfXchWhE14` | Local ignored DEVNET-only key; it is **not** a managed signer. A separate new non-exportable Transit identity is required. | Add the new managed pubkey through explicit policy versioning, validate it, then retire this bootstrap identity. |
| Vault Transit / remote signer | Isolates threshold-signing private keys and emits audit records. Not provisioned. | No endpoint, token, or key name is recorded in Git. The repository supports this backend for notary signing only. | Create versioned Transit keys with independent access policies; record their public-key/key-name mapping outside Git, revoke access, and rotate keys after any compromise. |
| Matching keeper | Devnet-only keeper authorization. `5sL3Z89NdNVYfCTrmnjzCcGHAtjHVJwodDyZswv1P19F` | Bootstrap: local ignored DEVNET-only key; runtime service is not provisioned. | Stop the keeper, rotate its managed identity, and review retry/audit logs. |
| Oracle attester and policy engine | Acquires evidence, evaluates 2/2 verifier policy, and persists conflicts. Not provisioned. | Required service credentials and storage are not provisioned. | Roll forward a versioned runtime configuration; revoke credentials and preserve conflict/audit state on compromise. |
| RPC and WebSocket | Devnet-only endpoints: `https://api.devnet.solana.com` and `wss://api.devnet.solana.com`. | Public endpoints require no secret. A production operated endpoint has not been provisioned. | Fail closed on a non-devnet genesis hash; change endpoints only through reviewed devnet configuration. |
| Monitoring and alert routing | Health, disagreement, rejection, equivocation, stale-evidence, and deployment alerts. Not provisioned. | Alert credentials must reside in the chosen monitoring secret store, never Git. | Rotate integration credentials and verify a replacement alert delivery path. |

The two bootstrap signer public keys are distinct, and the public-devnet
configuration requires two verifiers and two agreeing verifier results. Neither
signer alone satisfies the configured 2/2 policy. They cannot be imported into
non-exportable Vault Transit while preserving their identities, so identity
continuity with managed signers is currently unproven. Runtime enforcement and
equivocation/audit persistence remain deployment blockers until new managed
signers and policy services are provisioned.
