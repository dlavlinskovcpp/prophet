# Prophet Trust Model

This document describes what Prophet guarantees, what it assumes, and where the trust boundaries are.

## Scope

Prophet is a hybrid system:

- on-chain logic enforces custody, state transitions, and settlement
- off-chain services supply resolver data, zkTLS verification, and threshold signatures

The protocol is designed to make off-chain resolution auditable and constrained, not to eliminate off-chain trust entirely.

## Security Goals

Prophet aims to provide:

- on-chain custody of quote assets during market lifetime
- deterministic order, refund, redemption, and fee accounting under the program rules
- explicit governance controls around market lifecycle
- auditable market resolution via canonical messages plus stored `proof_hash` and `public_inputs_hash`
- threshold authorization for market resolution instead of single-signer resolution

## What The Program Enforces

The on-chain program enforces:

- market timing, status transitions, and authority permissions, including an enforceable `lock_ts`
- permanent schedule immutability after the first accepted order, even when current open-order count later returns to zero
- order placement constraints, escrow accounting, and fee reserve accounting
- matching math and payout logic
- fee-recipient and protocol-fee withdrawal rules
- canonical v2 resolution message format
- threshold signature count, distinct signer checks, and `NotaryConfig` version binding

If a submitted resolution does not match the expected message bytes or threshold rules, the chain rejects it.

## What The Program Does Not Enforce

The program does not prove:

- that public inputs came from a truthful external data source
- that the off-chain zkTLS verifier was correct in an absolute cryptographic sense
- that operators used a safe registry, signer, or RPC stack
- fairness of transaction ordering or liveness of external infrastructure

The chain stores hashes and verifies signatures, but it does not re-run zkTLS proof verification on-chain.

## Trusted Components

### Notary Set

Resolution depends on the configured threshold notaries. If enough notary keys sign a bad message, the chain cannot distinguish that from a valid signed resolution.

### Oracle Attester

The attester is trusted to:

- load the correct resolver
- evaluate the resolver correctly
- verify zkTLS payloads correctly
- ask signers to sign the right message

The attester is not trusted with final custody of market funds, but it is part of the resolution trust boundary.

### Resolver Registry

The registry is trusted as the source for canonical resolver definitions. The main safety property is that the resolver loaded off-chain must hash back to the market's on-chain `resolver_hash`.

If the registry is unavailable, resolution can stall. If it serves the wrong resolver, the hash mismatch should prevent signing or submission.

### Remote Signer / KMS

The signer layer is trusted to:

- authorize only allowed signer pubkeys
- keep key material protected
- sign only the intended canonical message

Compromise of enough notary keys compromises market resolution.

### Solana Cluster And RPC

Prophet inherits the normal Solana assumptions:

- the cluster executes the deployed program correctly
- RPC responses are sufficiently correct for clients and services to operate
- transactions can be submitted and confirmed with reasonable liveness

## Main Failure Modes

### Attester Outage

Effect:

- markets cannot be resolved through the operated path

What still holds:

- funds remain in program custody
- trading, refunds, and existing state stay governed by the program

### Remote Signer Or KMS Outage

Effect:

- threshold signatures cannot be collected
- resolution stalls

### Resolver Registry Outage

Effect:

- new resolver loads may fail
- resolution may rely on cache if stale-on-error is enabled

### Notary Key Compromise

Effect:

- if enough keys are compromised to satisfy threshold, a bad market resolution can be signed

Mitigation:

- threshold sizing
- KMS/HSM-backed keys
- signer allowlists
- audit logs
- operator monitoring and key rotation

### Operator Error

Effect:

- wrong resolver published
- wrong market schedule
- wrong fee recipient
- incorrect service config

Mitigation:

- release process
- ops runbooks
- explicit environment configs
- durable audit logs
- on-chain rejection of retroactive schedule updates and schedule mutation after first economic activity
- authority emergency `Invalid` resolution is unavailable before the market's advertised `resolve_ts`
- on-chain rejection of zero market limits, unusable notary keys, and threshold
  configurations that cannot fit in the canonical V2 resolution transaction

## Non-Goals

Prophet does not currently attempt to provide:

- fully trustless on-chain data verification
- censorship-resistant off-chain service operation
- decentralized notary discovery or automatic key governance
- complete economic protection against all thin-liquidity or manipulation scenarios

## Operational Requirements

To run Prophet safely in production:

- keep notary keys in KMS/HSM-backed infrastructure
- require auth and TLS for remote signer and registry endpoints
- monitor attester, signer, registry, and keeper health
- back up audit logs, proof store, resolver store, and keeper state
- rehearse rollback and restore procedures before releases

## In Short

Prophet is strongest where it is on-chain:

- custody
- accounting
- governance bounds
- payout settlement

Its main trust boundary is market resolution:

- resolver definition source
- zkTLS verification
- threshold notary signatures
- operator-managed infrastructure

That is why the operated path emphasizes registry integrity, signer isolation, audit logs, and threshold signatures rather than claiming fully trustless oracle resolution.
