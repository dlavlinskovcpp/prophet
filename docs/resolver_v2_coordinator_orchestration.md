# Resolver V2 coordinator orchestration

Phase 6B2b adds the in-process `ResolutionCoordinator` application boundary. It
connects the existing identity-bound verifier clients to the existing durable
SQLite coordinator state core; it does not add a coordinator HTTP API,
background worker, retry loop, signing, or settlement submission.

## Flow

For one canonical request (`market`, `resolver_definition`, `evidence`, and
`trust_model`), `resolve()` performs deterministic sequential work:

```text
register/reuse durable job
  -> call missing verifier A result and persist it through state core
  -> call missing verifier B result and persist it through state core
  -> return durable AGREED or CONFLICT state
```

The state core owns canonical job identity, result binding, idempotency,
equivocation protection, and A/B agreement semantics. The orchestrator never
compares verifier results itself and never writes SQLite directly.

## Durable resume behavior

Before any network call, the coordinator inspects the durable job:

- `AGREED` and `CONFLICT` return immediately with zero verifier calls.
- A result already present means A is not called again; only missing B work is
  attempted.
- B result already present is symmetric: only missing A work is attempted.
- On verifier A service failure, B is not called and the `PENDING` job remains
  resumable.
- On verifier B service failure after A was stored, A remains durable and the
  next explicit `resolve()` invocation calls only B.

This phase deliberately has no automatic retry. A later explicit invocation is
the resume mechanism, including after process or database restart.

## Result and failure semantics

A canonical `VerificationResultV2` with `REJECTED`/`INVALID` semantics is still
a verifier result. It is persisted and passed to the existing agreement engine;
it is not converted into a transport error. Conversely, timeout, connection,
authorization, malformed response, identity mismatch, and binding mismatch are
typed service failures: no synthetic verifier result is stored.

Verifier client wiring is fixed at construction:

```text
state slot A <-> verifier client A
state slot B <-> verifier client B
```

The expected full verifier descriptors are checked during construction. A
cross-wired client cannot populate the other slot, and no A-to-B, B-to-A, or
local-runtime fallback exists.

Correlation IDs are bounded operational metadata propagated to both calls. They
never alter canonical request bytes, durable job identity, verifier results, or
agreement semantics.

## Deferred to Phase 6B2c

Still outside this boundary are coordinator HTTP serving, fan-out/concurrency,
retry policy, queues/background workers, conflict operations, Vault/threshold
signing, Solana transactions, and Docker deployment.
