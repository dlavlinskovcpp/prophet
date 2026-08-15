# Resolver V2 Pyth Adapter

The Pyth adapter is an off-chain evidence adapter. It never submits a
transaction or changes `PROPHET_RESOLVE_V2`. A resolver definition fixes the
32-byte feed ID, Pyth network, Solana cluster genesis hash, Pyth account schema
version, adapter version, expected price exponent, publish-age limit,
confidence limit, trust-model descriptor, and numeric predicate.

## Numeric representation and evidence

Pyth price and confidence are decimal integer strings. A price represents
`price × 10^exponent`; no float is parsed or emitted. The canonical evidence
payload includes feed/network bindings, price, exponent, confidence, status,
publish timestamp and slot, and a SHA-256 hash of the raw account bytes. This
makes historical observations auditable without querying current RPC state.

The adapter accepts only `TRADING` price status. It rejects zero prices,
confidence greater than `abs(price) × max_confidence_bps / 10,000`, stale
publish timestamps, exponent/scale overflow, malformed canonical payloads,
and every resolver, adapter, trust-model, feed, network, or cluster mismatch.

## Predicate, replay, and multi-verifier behavior

The shared numeric predicate accepts only `<`, `<=`, `>`, `>=`, or `==` and
two explicit outcomes. Mantissas are aligned exactly to the lower exponent;
overflow rejects. The evidence envelope binds the resolver definition, while
the resolution bundle binds market, cluster, nonce, and signer policy, so old
or cross-market/resolver/cluster observations fail the pipeline freshness and
binding checks.

`IndependentOracleVerifier` independently parses Pyth evidence and performs
its own fixed-point comparison. A 2/2 policy requires both canonical results
to agree. Differing outcomes, evidence hashes, stale/fresh views, or predicate
boundary results enter persistent conflict state and cannot reach signing.

Trust remains in the configured Pyth network/RPC acquisition path and the
attester deployment. Operators must investigate a conflict and provide fresh
evidence or a policy-approved override; no automatic source selection occurs.
