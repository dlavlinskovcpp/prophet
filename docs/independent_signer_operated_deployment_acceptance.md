# Independent signer operated-deployment acceptance

`IndependentSignerDeploymentManifest` is a public, immutable declaration for
one independent signer service.  The pure acceptance function composes the
P0C3A topology validator with separate host, runtime-principal, administrator,
journal-storage, audit, and TLS-termination domain assertions.

For `public-devnet` and `mainnet`, both services must be production
`OPERATED_2OF2` configurations, externally exposed through HTTPS, with a
distinct TLS termination domain.  A manifest may represent positive worker and
execution-concurrency values, but operated acceptance requires exactly one of
each and reload disabled.  These are operated deployment requirements: P0C3C
does not itself enforce that concurrency bound.

Manifests bind to the exact service configuration fingerprint and signer public
identity.  They contain public identifiers and environment-variable names only;
they never contain or read tokens, private keys, Vault metadata, or RPC data.

Acceptance proves only that the supplied declarations satisfy policy.  It does
not cryptographically prove host, cloud-account, provider, storage, or ingress
independence.  Those claims require separately collected operational evidence
after deployment; acceptance neither starts services nor accesses live systems.
