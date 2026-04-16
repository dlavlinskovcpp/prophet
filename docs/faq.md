# Prophet FAQ And Glossary

This document answers the questions a new reader, integrator, or operator usually asks first.

## FAQ

### What is Prophet?

Prophet is a Solana prediction market protocol built for automated trading and operated market resolution. Trading, custody, fees, refunds, redemption, and lifecycle controls are on-chain. Resolution uses an off-chain attester plus threshold notary signatures and an on-chain finalization step.

### Is Prophet fully on-chain?

No.

The market and settlement logic are on-chain, but resolver loading, zkTLS verification, and threshold-signature collection are off-chain responsibilities.

### Is resolution permissionless?

Yes, submission is permissionless.

Anyone can submit `resolve_market_threshold` once they have enough valid notary signatures over the canonical message.

### Is resolution trustless?

No.

Resolution depends on:

- the configured threshold notary set
- the resolver definition source
- the off-chain zkTLS verification path
- the integrity of the signer and attester infrastructure

See `docs/trust_model.md`.

### What is a `resolver_hash`?

`resolver_hash` is the SHA-256 hash of a canonical JSON resolver definition. The market stores only the hash on-chain. Off-chain services must load a resolver definition that hashes back to that value.

See `docs/resolver_spec.md`.

### What is a `NotaryConfig`?

`NotaryConfig` is the on-chain threshold signer set for a market resolution flow. It stores:

- the threshold
- the allowed notary pubkeys
- a version number

The version is part of the canonical v2 resolve message, so signer-set updates invalidate old signatures.

### Why does Prophet need a matching keeper?

Orders are explicit on-chain accounts, but crossed-book discovery and match submission are off-chain responsibilities. The keeper watches open orders and submits `match_orders` when a valid cross exists.

### Does a user have to use the attester?

Not always.

For smoke tests or tightly controlled flows, a relayer can call `resolve_market_threshold(...)` directly through the SDK after constructing the correct message and signatures. For the operated production-shaped path, the attester is the intended integration point.

### What does the attester actually do?

The attester:

- loads market state
- loads the canonical resolver definition
- evaluates resolver logic against public inputs
- verifies zkTLS payloads
- obtains notary signatures
- submits the final resolution transaction

### What does the resolver registry do?

The registry is the canonical storage layer for resolver definitions. It lets operators publish, fetch, and audit resolver definitions by hash instead of relying on ad hoc local files.

### What does the remote signer do?

The remote signer isolates notary key material from the attester process. In this repo it supports:

- Vault Transit-backed Ed25519 signing through the bundled command wrapper
- generic command-backed signing for external KMS/HSM wrappers, plus AWS KMS compatibility

### What is the fastest way to see Prophet work end to end?

Use `docs/devnet_quickstart.md`.

That path uses a demo `1-of-1` notary config to prove the SDK and on-chain resolution path, not the full production trust model.

### What is the production-shaped path?

The intended operated path is:

- resolver registry
- attester
- remote signer
- matching keeper
- Prometheus and Grafana

See `docs/architecture.md`, `docs/ops_runbook.md`, and `docs/release_runbook.md`.

### How are fees handled?

Each market has:

- `fee_recipient`
- `protocol_fee_bps`
- `accrued_protocol_fees_atoms`

Orders prefund escrow plus fee reserve. Fees accrue only on taker executions. Unused fee reserve is returned through normal refund flows.

### Can market authorities change fees at any time?

No.

Fee config freezes after the first order.

### Can market authorities arbitrarily resolve markets?

No.

The normal path is threshold resolution. Governance can only force `Invalid` through the narrow emergency path when the market is already locked.

### What is the difference between `Open`, `Locked`, and `Resolved`?

- `Open`: trading is allowed
- `Locked`: trading is no longer allowed; market waits for final resolution or emergency invalidation
- `Resolved`: outcome is final and redemption is enabled

### What does the devnet quickstart prove, and what does it not prove?

It proves:

- build and deploy work
- market creation works
- direct threshold resolution works

It does not prove:

- attester correctness in production shape
- remote signer or KMS operation
- resolver registry availability
- matching keeper behavior
- monitoring, backup, restore, or rollback readiness

## Glossary

### Attester

The service that verifies external proof material and assembles threshold resolution transactions.

### Matching Keeper

The long-running service that discovers crossed books and submits `match_orders`.

### Market

The main on-chain account for a prediction market. It stores schedule, resolver commitment, fee config, governance authority, and final outcome state.

### Order

An on-chain account representing an open YES or NO order plus remaining escrow and fee reserve.

### Position

An on-chain account tracking a user’s matched YES/NO shares, pending refunds, and redemption state.

### Resolver Definition

The canonical JSON object that describes how off-chain public inputs should be interpreted to derive a market outcome.

### Resolver Registry

The canonical store and API for resolver definitions.

### Threshold Notary Resolution

The v2 flow where multiple notaries sign a canonical resolve message and the chain verifies a threshold of distinct signatures.

### zkTLS

The off-chain proof system used here to support authenticated web-data verification before a market is resolved.
