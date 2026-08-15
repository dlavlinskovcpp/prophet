# Vault Transit 2-of-2 signing

`ThresholdResolutionSigner` is an application-only boundary for one already serialized `PROPHET_RESOLVE_V2` message. It takes two fixed `VaultTransitSignerClient` instances in role order A then B. The clients retain ownership of Transit HTTP requests, metadata checks, public-key and key-version pinning, response parsing, and local Ed25519 verification.

The signer calls A once and, only after A succeeds, calls B once. A result exists only when both signatures verify against the same exact byte string and each configured pinned public key/version. There is no 1-of-2 result, retry loop, signer selection from request data, or degraded mode. The immutable `ThresholdSignatureBundle` is ordered A then B and carries only public identities, versions, signatures, and the SHA-256 digest of the signed canonical bytes. It is not a Solana instruction format.

The final bundle is checked again against the fixed A/B identities. Swapping slots, duplicating one signer, changing a key version, mutating the settlement bytes, or combining signatures produced for different messages fails closed. Runtime metadata such as configuration fingerprints and request IDs is not serialized into, or signed as part of, `PROPHET_RESOLVE_V2`.

This phase has no coordinator invocation, durable signing state, retry behavior, threshold policy decision, transaction construction, or transaction submission. Key rotation and persistent equivocation/retry handling remain outside this component.
