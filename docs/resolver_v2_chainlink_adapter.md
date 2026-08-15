# Resolver V2 Chainlink Adapter

The Chainlink adapter targets the configured Solana-compatible Chainlink data
source. It is strictly off-chain: it produces canonical Resolver V2 evidence
and verification results only, never a settlement transaction.

## Binding and fixed point semantics

Definitions bind the exact feed identity, network, cluster genesis hash,
decimals, data-source and adapter versions, staleness limit, required
round/update metadata, trust-model descriptor, and the shared numeric
predicate. An answer is an integer mantissa with effective exponent
`-decimals`. All inputs are decimal strings and comparisons use integer
scaling only; floats and arbitrary expressions are forbidden.

Canonical evidence preserves the answer, decimals, update timestamp, round ID,
`answered_in_round`, feed/network bindings, and raw account-data hash. It
therefore identifies the historical observation independently of mutable RPC
state. Missing or malformed data, wrong bindings/decimals, stale timestamps,
or invalid round metadata (`round_id == 0` or `answered_in_round < round_id`)
are rejected fail closed.

## Freshness, replay, and disagreement

An evidence envelope commits to the resolver definition and adapter digest;
the V2 bundle commits it further to market, cluster, resolution nonce and
signer policy. Previously valid observations expire at `updated_at_ms +
max_answer_age_ms` and cannot be replayed across those domains.

Primary and `IndependentOracleVerifier` implementations consume identical
canonical evidence but parse and compare it independently. Multi-verifier
policy can require 2/2. Different rounds/timestamps, stale-vs-fresh results,
confidence or predicate-boundary disagreement, and differing evidence hashes
are classified as conflicts. Persistent conflict state blocks signing until
fresh evidence or an explicit policy-approved reconciliation is recorded.

Residual trust is in the configured Chainlink Solana data source and in both
verifier deployments. Metrics expose fetch failures, stale observations,
adapter latency, resolution success/failure and multi-verifier disagreement.
