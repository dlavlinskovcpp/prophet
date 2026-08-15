# Resolver V2 signing recovery

The signing sequence is durable-before-network for each fixed signer role: reserve the canonical intent; commit the per-signer operation marker; call Vault; locally validate response/version/Ed25519 signature; then atomically store the public signature and completed operation state.

`INTENT_RECORDED` means neither signer was called. `A_SIGNING` means A's operation marker committed but no durable signature exists; it is exposed as A `SIGNATURE_STATUS_UNKNOWN`. `A_SIGNED` means A's signature is durable and B is `NOT_STARTED`. `B_SIGNING` means B is unknown while A remains recorded. `BOTH_SIGNED` means the immutable 2-of-2 bundle is complete.

The operation marker is intentionally conservative. A crash after it but before a Vault call cannot be reliably distinguished from a crash after Vault may have signed and before persistence. Both are uncertain after restart. No automatic retry is permitted, and repeated exact-message recovery remains blocked without making another Vault call. The deterministic test backend may return deterministic Ed25519 signatures, but this implementation does not infer that an external Vault Transit service has identical replay guarantees.

`inspect_recovery` and `scan_recovery` are read-only startup/operational APIs that expose scope, digest, per-signer states, category, and timestamps. `resume_2_of_2` is explicit: completed signatures are reused with zero Vault calls; A durable/B not-started can continue sequentially; uncertain A or B rejects. It accepts only the original exact canonical message—another digest for the same scope fails anti-equivocation checks before Vault.

This phase has no key rotation, coordinator integration, automatic worker, generic retry policy, transaction construction, or Solana submission.
