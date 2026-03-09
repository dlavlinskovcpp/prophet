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

- Market setup: `initialize_market_v2` (primary), `initialize_market` (legacy compatibility)
- Notary admin: `initialize_notary_config`, `update_notary_config`
- Trading: `place_order`, `match_orders`, `cancel_order`
- Funds: `claim_refunds`, `redeem`
- Resolution: `resolve_market_threshold` (primary), `resolve_market_signed` / `resolve_market` (legacy compatibility)

## Off-Chain Components

Service: `apps/oracle-attester`

Responsibilities:

- Load market state and resolver definition
- Verify resolver predicate against provided public inputs
- Verify zkTLS payload using Reclaim HTTP verifier
- Build resolve message/signatures
- Submit permissionless resolve transaction for v2 threshold markets by default

## Resolution Trust Model (MVP)

- zkTLS verification is off-chain in attester.
- On-chain verifies Ed25519 signatures and message canonicality.
- On-chain stores `proof_hash` + `public_inputs_hash` for auditability.
- Threshold mode reduces trust by requiring distinct t-of-n notary signatures.
- Legacy single-oracle resolution remains for compatibility, but the attester should treat it as opt-in only.

## Agent Integration

SDK: `sdk/python/prophet_sdk`

Target usage:

- place/match/cancel loops by autonomous agents
- deterministic retries (`place_order_auto_seq`)
- direct resolution flows for oracle/relayer agents
