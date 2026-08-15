# Resolver V2 runtime adapter factory

The factory selects an adapter from canonical Resolver V2 metadata only. The
lookup key is the resolver definition's `resolver_type` and the complete
adapter descriptor tuple: `adapter_id`, `adapter_version`, and
`implementation_digest`. The resolver definition is validated before lookup.
There is no caller-supplied adapter selector.

`RuntimeAdapterRegistry` is an immutable allowlist for the existing zkTLS,
signed-oracle, Pyth, and Chainlink families. Each frozen runtime descriptor
records the canonical identity, a stable runtime implementation identifier, and
its required startup dependencies. Unknown types, versions, or digests have no
entry and fail closed. Duplicate canonical identities are rejected while the
registry is constructed.

The factory enforces `allowed_adapters` before instantiation. zkTLS construction
delegates to `ZkTlsAdapter.from_runtime`, so it receives only the explicitly
configured proof-verifier backend. Signed-oracle construction delegates to
`SignedOracleAdapter.from_runtime`, requiring the immutable runtime registry
and `LegacyKeyBinding` collection and yielding `RegistryBackedOracleKeyring`.
Pyth and Chainlink have no additional runtime dependency in their existing
constructors; their feed, network, freshness, and predicate validation remains
inside those adapters.

The factory does not verify evidence, select oracle keys, evaluate predicates,
normalize evidence, or implement adapter-specific policy. It does not alter
canonical resolver serialization or hashes. Adapter implementation identifiers
are fixed code allowlist metadata; the canonical descriptor and runtime
configuration fingerprint already bind the security-relevant selection inputs.

`runtime.verify()` and request routing remain outside this phase.
