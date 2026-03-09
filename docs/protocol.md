# Prophet Protocol (MVP)

Prophet is a Solana/Anchor binary prediction market protocol optimized for bot execution.

## On-Chain Components

Program: `programs/prophet`

Main accounts:

- `Market`: lifecycle config, resolver hash, proof/public-input hashes, settlement state
- `Order`: open order escrow + limit probability
- `Position`: matched YES/NO shares + pending refunds + redemption status
- `NotaryConfig`: threshold notary set for `resolve_market_threshold`

Main instructions:

- Market setup: `initialize_market_v2`
- Notary admin: `initialize_notary_config`, `update_notary_config`
- Market governance: `transfer_market_authority`, `lock_market`, `unlock_market`, `sync_market_status`, `update_market_schedule`, `set_market_fee_config`, `withdraw_protocol_fees`, `emergency_resolve_invalid`
- Trading: `place_order`, `match_orders`, `cancel_order`
- Funds: `claim_refunds`, `redeem`
- Resolution: `resolve_market_threshold`

Lifecycle notes:

- `MarketStatus::Locked` is now a real lifecycle state, not just an enum placeholder.
- Authority can manually lock/unlock a market and transfer governance to a new authority.
- Anyone can call `sync_market_status` once `lock_ts` has passed to materialize the scheduled `Locked` state on-chain.
- Schedule updates are intentionally narrow: they require the market to be unresolved, pre-lock, and to have zero open orders.
- Fee configuration is also intentionally narrow: `set_market_fee_config` is authority-only and freezes permanently after the first order (`next_order_seq > 0`).
- Emergency governance can only force `Invalid`, not arbitrary `Yes` / `No`.

Economics notes:

- Each market carries a `fee_recipient`, `protocol_fee_bps`, and `accrued_protocol_fees_atoms`.
- `place_order` prefunds both order escrow and a fee reserve derived from the order's maximum escrow requirement.
- `match_orders` only accrues protocol fees on the taker side of each execution, so maker liquidity is not charged for resting on the book.
- Any unused fee reserve is returned through the normal refund path when an order is fully filled or cancelled.
- `withdraw_protocol_fees` is authority-only and can only transfer already accrued protocol fees from the market quote vault to the configured treasury recipient.

## Off-Chain Components

Service: `apps/oracle-attester`

Responsibilities:

- Load market state and resolver definition
- Verify resolver predicate against provided public inputs
- Verify zkTLS payload using Reclaim HTTP verifier
- Build resolve message/signatures
- Submit permissionless resolve transaction for v2 threshold markets by default
- Persist durable audit records for verification and submission steps
- Cache resolver definitions from the registry and serve stale cached entries during transient registry failures
- Publish canonical resolver definitions through an immutable resolver registry service before attestation

## Resolution Trust Model (MVP)

- zkTLS verification is off-chain in attester.
- On-chain verifies Ed25519 signatures and message canonicality.
- On-chain stores `proof_hash` + `public_inputs_hash` for auditability.
- Threshold mode reduces trust by requiring distinct t-of-n notary signatures.
- Resolver definitions should come from a canonical registry source (directory mirror or HTTP registry) and must hash back to the on-chain `resolver_hash`.
- The bundled resolver registry service provides authenticated publish/load APIs, durable audit logs, and a canonical file-backed store that the attester can consume over HTTP.
- Managed signer deployments should keep an explicit signer allowlist. The repo now includes a concrete AWS KMS Ed25519 backend and still supports command/KMS/HSM bridges for other signer providers.

## Agent Integration

SDK: `sdk/python/prophet_sdk`

Target usage:

- place/match/cancel loops by autonomous agents
- deterministic retries (`place_order_auto_seq`)
- direct resolution flows for oracle/relayer agents
