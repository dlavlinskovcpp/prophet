# Resolver V2 runtime verification

`ResolverVerifierRuntime` is an in-process boundary for one configured verifier
implementation. It is constructed at startup from immutable runtime
configuration, a `RuntimeAdapterFactory`, and one canonical verifier descriptor.
The descriptor identity and version must equal the configured verifier identity.

`runtime.verify()` accepts the existing canonical resolver definition, evidence
envelope, and trust-model descriptor. It validates those inputs and their
definition/trust bindings, asks the factory to select an adapter from canonical
resolver metadata, invokes that adapter, then converts the existing
`VerificationReport` with `verification_result_from_report`. It does not define
a new request or result schema.

There is no adapter override parameter. Selection derives only from resolver
type plus canonical adapter ID, version, and digest. Runtime-only metadata,
including configuration fingerprints, signed-oracle registry data,
`LegacyKeyBinding`, and zkTLS backend IDs, is not serialized into evidence or
verification results.

The factory supplies the explicit zkTLS proof backend and the registry-backed
signed-oracle keyring. Pyth and Chainlink retain their existing construction and
verification paths. Structural failures and factory/dependency failures reject
at the runtime boundary; adapter verification failures produce their existing
canonical rejected result.

This phase deliberately does not implement HTTP, request routing, multi-verifier
coordination, persistence, Vault signing, or settlement submission.

## Independent runtime instances

Two runtime instances may consume the same canonical request and equivalent
public runtime trust inputs while remaining separate execution paths:

`VerifierRuntime A → primary adapter implementation`

`VerifierRuntime B → IndependentZkTlsVerifier`

Each runtime is bound to its own verifier identity/version and cannot relabel
the other implementation. The independent zkTLS factory validates canonical
adapter identity through the same immutable registry, then invokes the existing
independent verifier and checker directly; it never invokes the primary adapter.
There is no comparison, aggregation, quorum calculation, conflict persistence,
signing, or resolution decision at this layer. No deterministic behavioral
disagreement fixture exists for the two real implementations, so this layer
only exposes their separate canonical verification results.
