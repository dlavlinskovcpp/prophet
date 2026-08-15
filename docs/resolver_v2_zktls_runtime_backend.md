# zkTLS runtime proof backend

`ZkTlsAdapter.verify` remains the source-of-truth verification boundary. It
first validates the canonical Resolver V2 evidence, resolver definition, source
domain, request binding, cluster domain, proof version, and freshness. It then
passes proof bytes, response bytes, and a frozen expected binding to the
explicit `ZkTlsProofVerifier` dependency. Returned claims are checked against
that same binding before response selection and outcome normalization.

Runtime configuration selects one backend by an allowlisted identifier. There
is no global verifier, dynamic import, network fallback, or default verifier.
If zkTLS is enabled, `provider_id`, `verifier_backend`, and a non-empty set of
allowed proof versions are required. These public values are included in the
non-secret runtime configuration fingerprint; proof-version ordering is
canonicalized.

`deterministic-test` is the only backend implemented in this phase. It accepts
only the explicit `b"proof"` fixture contract and is allowed solely when runtime
mode is `test`. Production configuration rejects it, and any other configured
backend fails closed because no production backend is implemented here.

The backend is selected at runtime construction through
`ZkTlsAdapter.from_runtime`; evidence cannot select a provider or backend. The
adapter retains the existing canonical evidence format and all existing
binding, freshness, response, and settlement behavior. This phase does not add
a provider implementation, networking, adapter routing, or a verifier service.
