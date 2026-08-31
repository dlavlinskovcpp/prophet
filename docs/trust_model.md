# Prophet Trust Model

Prophet is a hybrid protocol. The Solana program enforces financial state and
settlement authorization; Resolver V2, verifiers, and fixed-role signers are
off-chain dependencies. The design makes those dependencies explicit and
auditable, not trustless by assertion.

## Security goals

Prophet aims to provide:

- on-chain custody, accounting, lifecycle, refunds, fees, and redemption;
- immutable market binding to a canonical resolver and notary snapshot;
- exact 2-of-2 authorization for current Market V2 settlement;
- independent, role-local authorization before any settlement signature; and
- fail-closed handling of replay, equivocation, ambiguity, and unsupported
  resolver or notary inputs.

## What the Solana program enforces

The program enforces market timing and lifecycle rules, order and escrow
accounting, matching arithmetic, fee accounting, refunds, redemption, the
canonical resolution message, and the distinct-signature threshold. Each
Market V2 account pins an immutable `NotaryConfig` snapshot. Rotation creates a
successor for new markets; it does not rewrite an existing market's trust root.

The chain rejects malformed or mismatched settlement bytes and stores the
outcome, `proof_hash`, and `public_inputs_hash` after successful authorization.

## What the program does not enforce

The program does not prove that an external data source is truthful, that an
off-chain verifier interpreted evidence correctly, or that operators selected
a safe resolver registry, RPC, or runtime. zkTLS verification occurs off-chain;
the chain does not verify zkTLS proofs itself.

Matching is **permissionless limit-order crossing**. The program validates a
caller-selected crossing pair, but does not provide consensus-enforced global
top-of-book, global best execution, strict price priority, strict time priority,
or Sybil-resistant economic identity.

## Fixed-role signer boundary

Current production settlement uses fixed-role Signer A and fixed-role Signer B.

> No production process can possess or accept both Signer A and Signer B
> credentials.

The roles are independent across runtime principal, administration, admission
issuer, Vault authentication and key identity, finalized RPC trust path, and
durable journals. A signer performs:

```text
strict request parsing
  -> admission G1
  -> durable replay G2
  -> independent P0C1 authorization
  -> P0C2 anti-equivocation
  -> role-local Vault signing
```

The coordinator/broker is only a cache and transport boundary. It is not an
authorization authority and has no signer credentials. A submitter and matching
keeper are also not signers.

### Compromise and failure consequences

- Compromising one signer domain is insufficient for an exact 2-of-2 outcome.
- Compromising both pinned signer domains can authorize a false outcome.
- A compromised signer RPC can corrupt that signer's view of finalized state.
  Independent A/B RPC domains are therefore an operational security gate, not
  an optional deployment detail.
- A compromised coordinator can submit bad requests or cause denial of
  service, but should not directly authorize settlement.
- A lost or unavailable pinned key can permanently block resolution for markets
  bound to that exact 2-of-2 snapshot. This is a deliberate current liveness
  tradeoff, not an implicit recovery guarantee.

## Resolver and verifier trust

Resolver V2 definitions are canonical machine-readable market commitments. A
non-zero `resolver_hash` is required for Market V2. Permissionless creation of
that commitment does not mean the Prophet-operated resolver service supports
every definition.

Verifier A and Verifier B evaluate evidence and return authenticated results.
Their output remains part of the off-chain trust boundary. The registry stores
and serves definitions, but cannot self-authorize settlement. The signers must
bind any result to the market's resolver hash and the configured policy before
signing.

## Readiness and liveness

`/live` means the process is running. `/ready` checks dependencies and fails
closed; it must not create a settlement signature merely to report readiness.
Before the Prophet public-devnet program exists, settlement readiness may
remain blocked with an `expected_program_missing` reason.

Resolution is permissionless to submit after valid authorization is assembled,
but it depends on verifier, signer, Vault, RPC, registry, and transaction
submission availability. Internal security acceptance and green CI are
regression evidence, not an independent audit.

## Operational requirements

An operated deployment should:

- keep Signer A and Signer B in separate credential and fault domains;
- use non-exportable role-local Vault keys and scoped admission policies;
- use independent finalized-RPC trust paths;
- persist G2 and P0C2 state on distinct durable storage;
- protect TLS, private service ingress, metrics, and operator endpoints;
- monitor verifier, signer, Vault, RPC, registry, coordinator, and keeper
  liveness; and
- rehearse backup, restart, key-loss, and ambiguous-submission procedures.

## Current status

The current release candidate is `v1.0.0-rc4.7` with CI green. Public-devnet
is paused and its Prophet program is not deployed. Mainnet is blocked, and an
external independent audit is required before significant mainnet TVL.

## Summary

Prophet's strongest guarantees are on-chain custody, accounting, lifecycle
rules, and final authorization. Its remaining trust boundary is the complete
off-chain resolution path: canonical resolver data, independent verifier
correctness, two fixed-role signer domains, Vault and RPC security, and
operator-controlled availability.
