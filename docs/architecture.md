# Prophet Architecture

This document is the high-level map of Prophet as a system. Use it before diving into protocol details or operator runbooks.

## Overview

Prophet splits responsibility across an on-chain market program and several off-chain services:

- the Anchor program owns custody, order state, settlement, governance, and final resolution state
- the SDK is the user and agent entrypoint for market creation, trading, governance, and resolution
- the attester evaluates resolver logic, verifies zkTLS payloads, and assembles canonical resolve transactions
- the resolver registry stores canonical resolver definitions keyed by `resolver_hash`
- the remote signer manages notary keys outside the attester process
- the matching keeper discovers open orders and submits `match_orders` for crossed books

## Component Diagram

```text
                    +----------------------+
                    |  Resolver Registry   |
                    | canonical resolvers  |
                    +----------+-----------+
                               ^
                               |
                    +----------+-----------+
                    |      Oracle Attester |
                    | resolver eval +      |
                    | zkTLS verify +       |
                    | resolve assembly     |
                    +----------+-----------+
                               |
                               v
                    +----------+-----------+
                    |     Remote Signer    |
                    | KMS / command bridge |
                    +----------+-----------+
                               |
                               v
+-------------------+  txs  +--+------------------+  txs  +-------------------+
| Traders / Agents  +------->   Prophet Program   <-------+ Matching Keeper   |
| SDK / scripts     |       | custody + matching  |       | crossed-book loop |
+-------------------+       | governance + settle |       +-------------------+
                            +-----------+----------+
                                        |
                                        v
                               +--------+--------+
                               | Solana Accounts |
                               | Market / Order  |
                               | Position /      |
                               | NotaryConfig    |
                               +-----------------+
```

## On-Chain State

The core accounts are:

- `Market`: resolver commitment, timing, governance authority, fee config, and final resolution state
- `Order`: live order state, remaining escrow, and fee reserve
- `Position`: matched shares, pending refunds, and redemption state
- `NotaryConfig`: threshold, member keys, and version used by v2 resolution messages

The program is the source of truth for:

- market timing and lifecycle
- custody of quote assets in the market vault
- open orders and matched share balances
- protocol fee accrual and withdrawal
- final resolved outcome plus `proof_hash` and `public_inputs_hash`

## Off-Chain Responsibilities

### Python SDK

The SDK is the standard interface for:

- creating and governing markets
- placing, matching, cancelling, refunding, and redeeming
- direct threshold resolution for relayer or operator flows

### Oracle Attester

The attester is responsible for:

- loading the current market state
- loading the canonical resolver definition
- evaluating resolver logic against public inputs
- verifying zkTLS payloads
- obtaining threshold signatures
- submitting the final `resolve_market_threshold` transaction

### Resolver Registry

The registry stores canonical resolver definitions and lets operators:

- publish a resolver once
- retrieve a resolver by hash
- audit what definition was published for a given market

### Remote Signer

The signer keeps notary key material outside the attester process. In this repo it supports:

- AWS KMS-backed Ed25519 signing
- command-backed signing for other KMS/HSM wrappers

### Matching Keeper

The keeper handles the off-chain part of the order book:

- discovers eligible markets
- indexes open orders
- detects crossed books
- submits `match_orders`

## Common Flows

### Trading Flow

1. An operator creates a market with a `resolver_hash`, quote mint, schedule, and `NotaryConfig`.
2. Agents place `BuyYes` and `BuyNo` orders on-chain.
3. The keeper or any relayer submits `match_orders` when orders cross.
4. Traders claim refunds and later redeem winning shares on-chain.

### Resolution Flow

1. The market reaches `resolve_ts`.
2. The attester loads the resolver definition that matches the market's `resolver_hash`.
3. The attester verifies public inputs and zkTLS proof material.
4. Distinct notaries sign the canonical v2 resolve message.
5. Any relayer submits `resolve_market_threshold`.
6. The program verifies threshold signatures and finalizes the market.

## Deployment Shapes

### Developer Smoke Path

Use the SDK directly with a small threshold set, often `1-of-1`, to:

- deploy the program
- create a market
- resolve it directly with `resolve_market_threshold`

This is the fastest integration path, but not the production trust model.

### Operated Path

Use the full service stack:

- resolver registry
- attester
- remote signer
- matching keeper
- Prometheus and Grafana

This is the intended production shape for Prophet.

## Mutable Off-Chain State

Operators should treat these as owned runtime state:

- `resolver_store/`
- `proof_store/`
- `audit/`
- `apps/matching-keeper/state/`

Backup and restore procedures are documented in `docs/ops_runbook.md`.

## Read Next

- Protocol details: `docs/protocol.md`
- Security assumptions and boundaries: `docs/trust_model.md`
- Minimal deploy-to-resolution path: `docs/devnet_quickstart.md`
- Release and rollback: `docs/release_runbook.md`
