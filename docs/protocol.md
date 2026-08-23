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
- Notary admin: `initialize_notary_config`, `rotate_notary_config` (`update_notary_config` is retained only as a fail-closed legacy ABI)
- Market governance: `transfer_market_authority`, `lock_market`, `unlock_market`, `sync_market_status`, `update_market_schedule`, `set_market_fee_config`, `withdraw_protocol_fees`
- Trading: `place_order`, `match_orders`, `cancel_order`
- Funds: `claim_refunds`, `redeem`
- Resolution: `resolve_market_threshold`

Lifecycle notes:

- `MarketStatus::Locked` is now a real lifecycle state, not just an enum placeholder.
- `lock_ts` is an enforceable trading horizon: authority `lock_market` calls are rejected before `lock_ts`; anyone can still call `sync_market_status` at or after `lock_ts` to materialize the scheduled `Locked` state.
- Authority may transfer governance, but it cannot shorten the advertised trading horizon through an early manual lock. `unlock_market` remains bounded by the existing `now < lock_ts` rule.
- Schedule updates are intentionally narrow: they require the market to be unresolved and pre-lock, the replacement `lock_ts` to be strictly in the future, `resolve_ts >= lock_ts`, and `next_order_seq == 0`.
- `next_order_seq` is the durable economic-activity marker. After the first accepted order, schedule timing is permanently immutable even if all orders later fill or cancel and `open_orders_total` returns to zero.
- Fee configuration is also intentionally narrow: `set_market_fee_config` is authority-only and freezes permanently after the first order (`next_order_seq > 0`).
- `NotaryConfig` is an immutable trust-root snapshot. Version 1 preserves the deployed legacy PDA `[b"notary_config", admin]`; successor versions use `[b"notary_config", admin, version_le_u64]` and are created only by `rotate_notary_config`.
- `Market.notary_config` permanently pins the exact snapshot selected at market initialization. Creating a successor does not retarget, rewrite, or invalidate an older unresolved market, and zero-copy/in-place mutation through legacy `update_notary_config` is rejected.
- `PROPHET_RESOLVE_V2` remains byte-for-byte compatible: its existing notary-config address and `version` fields bind signatures to the pinned immutable snapshot, so rotation does not require a new settlement domain or account layout.
- `resolve_market_threshold` is the only resolution instruction. It is the sole path for `Yes`, `No`, and `Invalid`; an authority cannot settle, alter proof hashes, or bypass the pinned threshold-notary authorization after `resolve_ts`.

Economics notes:

- Each market carries a `fee_recipient`, `protocol_fee_bps`, and `accrued_protocol_fees_atoms`.
- `place_order` prefunds both order escrow and a fee reserve derived from the order's maximum escrow requirement.
- `match_orders` only accrues protocol fees on the taker side of each execution, so maker liquidity is not charged for resting on the book.
- Any unused fee reserve is returned through the normal refund path when an order is fully filled or cancelled.
- Invalid-outcome redemptions carry half-atom rounding between claimants, so aggregate payouts conserve the market's matched collateral even when individual positions are odd-sized.
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
- Load canonical resolver definitions from an immutable resolver registry service before attestation

## Resolution Trust Model (MVP)

- zkTLS verification is off-chain in attester.
- On-chain verifies Ed25519 signatures and message canonicality.
- On-chain stores `proof_hash` + `public_inputs_hash` for auditability.
- Threshold mode reduces trust by requiring distinct t-of-n notary signatures.
- Canonical V2 transactions support a maximum threshold of two because each
  self-contained signature repeats the 235-byte resolve message and the current
  client path uses Solana legacy transactions. Larger notary sets remain useful
  for rotation and availability, but `threshold` must be `1` or `2`.
- Resolver definitions should come from a canonical registry source (directory mirror or HTTP registry) and must hash back to the on-chain `resolver_hash`.
- The bundled resolver registry service provides authenticated publish/load APIs, durable audit logs, and a canonical file-backed store that the attester can consume over HTTP.
- Managed signer deployments should keep an explicit signer allowlist. The repo now ships a Vault Transit signer wrapper for the operated path and still supports generic command/KMS/HSM bridges plus the legacy AWS KMS backend.
- A verifier, signer, or Vault outage is a liveness and recovery condition: without valid threshold authorization, the market remains unresolved. Market authority has no settlement fallback.

## Agent Integration

SDK: `sdk/python/prophet_sdk`

Target usage:

- place/match/cancel loops by autonomous agents
- deterministic retries (`place_order_auto_seq`)
- direct resolution flows for oracle/relayer agents
