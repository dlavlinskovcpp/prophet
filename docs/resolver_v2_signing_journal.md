# Resolver V2 signing journal

The signing journal is a SQLite-only, fail-closed persistence boundary for the Vault Transit 2-of-2 signer. It is not called by the coordinator and it does not construct or submit Solana transactions.

## Scope and intent

The scope is a SHA-256 commitment to the fixed `PROPHET_RESOLVE_V2` domain plus all message fields through `notary_config_version`: program, market, notary configuration, resolver hash, opening timestamp, resolution timestamp, and configuration version. Outcome, proof hash, and public-input hash are intentionally excluded so alternative outcomes or evidence commitments for the same settlement identity collide. A scope can bind exactly one full canonical message digest and byte string.

Before Vault is called, the journal commits the intent and a per-signer `A_SIGNING` or `B_SIGNING` reservation. The returned public signature is stored only after it verifies against the exact bytes held by the journal. The state sequence is `INTENT_RECORDED` → `A_SIGNING` → `A_SIGNED` → `B_SIGNING` → `BOTH_SIGNED`.

Exact duplicate intents and byte-exact signer results are idempotent. Different messages, signer identities, versions, public keys, or signatures cannot overwrite prior records. Completed bundles are immutable.

If a process crashes after durable `*_SIGNING` reservation but before storing Vault's response, the journal records an uncertain state and refuses a blind re-sign. This avoids assuming deterministic or replay-safe Vault behavior. An explicit recovery policy is deferred.

No key rotation, automatic retry, persistence in coordinator state, coordinator signing integration, or settlement submission is part of this phase.
