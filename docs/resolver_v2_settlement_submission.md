# Resolver V2 settlement submission and reconciliation (Phase 6D3)

Phase 6D3 adds one explicit in-process execution boundary for an already durable
`AGREED` settlement. It extends the completed Phase 6D1/6D2 path with durable
transaction-attempt persistence, one exact Solana submission, status reconciliation,
and restart-safe fail-closed behavior.

It does **not** automatically submit from `coordinator.resolve()` or
`sign_agreed_job()`, and it does not add a background worker or public settlement HTTP
endpoint.

## Existing authorization remains authoritative

Resolution authorization is still the immutable Vault A/B Ed25519 2/2 bundle over the
exact existing `PROPHET_RESOLVE_V2` bytes. Phase 6D3 never changes those bytes,
signatures, signer epochs, coordinator agreement, or signing-journal semantics.

The dedicated Solana fee payer from Phase 6D2 signs only the transaction envelope.
Once a signed transaction attempt exists, status reconciliation does not require the
fee-payer private key, Vault, or verifier services.

## Exact execution path

A first explicit `submit_settlement(job_id)` call follows this order:

1. load the durable coordinator-to-signing linkage;
2. use Phase 6D2 to validate RPC genesis, acquire a recent blockhash, invoke the
   existing Phase 6D1 transaction builder, fee-payer-sign the transaction, and simulate
   the exact signed candidate;
3. require the simulation result to be `READY_CANDIDATE`;
4. durably insert a `PREPARED` transaction attempt containing the exact serialized
   signed transaction bytes and their SHA-256 digest;
5. commit `PREPARED`;
6. atomically transition that attempt to `SUBMISSION_STARTED` and commit;
7. only the caller that won the `PREPARED -> SUBMISSION_STARTED` transition may call
   the narrow `submit_exact_transaction()` RPC method;
8. validate the RPC-returned Solana signature against the locally known fee-payer
   transaction signature;
9. persist `SIGNATURE_KNOWN` when the response is unambiguous;
10. perform one explicit signature-status reconciliation pass.

The bytes passed to `sendRawTransaction` are therefore exactly:

```
Phase 6D2 simulated signed bytes
== durable attempt serialized_transaction
== submitted bytes
```

There is no rebuild between simulation and send.

## Transaction attempt journal

`SettlementAttemptJournal` is a separate SQLite persistence boundary for blockchain
execution state. It does not own coordinator or signing state.

Each attempt stores public/security-relevant data including:

- attempt ID;
- coordinator job ID;
- signing intent ID;
- canonical settlement digest;
- exact signed transaction bytes;
- transaction digest;
- fee-payer public key;
- recent blockhash;
- expected Prophet program ID;
- cluster and genesis hash;
- locally known Solana transaction signature;
- submission/confirmation state;
- slot and transaction error when known;
- failure/reconciliation category;
- timestamps.

Private keys, Vault tokens, and RPC credentials are never persisted.

A row-binding digest covers the immutable transaction identity and mutable execution
status fields so malformed/tampered historical rows fail closed. SQLite constraints
allow only one active attempt for a signing intent and prevent competing exact
candidates.

## Submission state model

Phase 6D3 uses these explicit states:

- `PREPARED` — exact signed transaction is durably recorded and no submission marker
  has been committed;
- `SUBMISSION_STARTED` — the durable send marker is committed; blind resend is now
  forbidden;
- `SIGNATURE_KNOWN` — RPC returned the same transaction signature already known
  locally;
- `PENDING` — RPC reports the signature but required commitment is not yet reached;
- `CONFIRMED` — the exact signature is observed at or above configured commitment with
  no transaction error;
- `FAILED_FINAL` — a landed transaction error or terminal pre-submission simulation
  rejection has been durably classified;
- `STATUS_UNKNOWN` — submission/status outcome is ambiguous and must be reconciled;
- `EXPIRED_UNSUBMITTED` — a durable `PREPARED` candidate is proven stale by exact-byte
  re-simulation before any submission marker/send.

State changes are methods on the journal; callers cannot assign arbitrary states.

## Persist-before-send rule

`sendRawTransaction` is never invoked from `PREPARED` directly. The service first
commits `SUBMISSION_STARTED`. This deliberately makes a crash immediately before the
network call conservative: after restart the attempt is treated as potentially sent
and is reconciled before any further chain-affecting action.

This may leave an attempt ambiguous even when a crash actually occurred before bytes
reached the RPC. Phase 6D3 prefers safety over an unsafe double execution.

## Local Solana transaction signature identity

The Phase 6D2 fee payer produces a deterministic transaction signature before RPC
submission. Phase 6D3 stores that signature with `PREPARED` and uses it as the
canonical reconciliation identity.

The RPC-returned signature is parsed again with real solders and must equal the local
first transaction signature exactly. Mismatch or malformed response fails closed.
After an ambiguous send the same local signature is used with `getSignatureStatuses`;
no synthetic submission identifier is created.

## Ambiguous-send semantics

A transport timeout or disconnect after `SUBMISSION_STARTED` is **not proof that the
transaction was not submitted**. The service persists/retains `STATUS_UNKNOWN` and does
not blindly call send again.

This includes the critical case where the RPC receives and forwards the transaction
but the connection fails before the client receives a response.

A missing signature status also is not treated as proof of non-submission. An ambiguous
attempt remains ambiguous until a later explicit reconciliation observes sufficient
chain/RPC evidence.

## Reconciliation before retry

For `SUBMISSION_STARTED`, `STATUS_UNKNOWN`, `SIGNATURE_KNOWN`, or `PENDING`, every
subsequent `submit_settlement()` call takes the reconciliation path first. Before any
RPC status lookup it proves the durable attempt still matches the configured cluster,
Prophet program ID, and genesis hash. It performs no new blockhash acquisition,
transaction construction, fee-payer signing, or send.

`reconcile_settlement(job_id)` is an explicit read/reconciliation operation and never
submits.

Read/status reconciliation may be explicitly retried by an operator because it does
not mutate chain state. Transaction submission is different: Phase 6D3 does not
automatically retry it after an ambiguous outcome.

## Restart behavior

The transaction-attempt journal is genuine SQLite persistence and is reopened on
restart.

- restart from `PREPARED`: validate the configured cluster, Prophet program ID, and RPC
  genesis binding, re-simulate the exact durable signed bytes without a new blockhash
  or signature, then send only if that exact candidate is still simulation-valid;
- restart from `SUBMISSION_STARTED` or `STATUS_UNKNOWN`: query the locally known
  transaction signature before any possible send;
- restart from `SIGNATURE_KNOWN` or `PENDING`: reconcile the same signature;
- restart from `CONFIRMED`: return the durable terminal result with zero sends, no new
  blockhash, and no rebuild/re-sign.

Reconciliation of an existing attempt does not require the fee-payer private key.

## Blockhash expiry

Before any submission marker/send, exact-byte re-simulation may prove the durable
candidate has a stale blockhash. It transitions from `PREPARED` to
`EXPIRED_UNSUBMITTED`; Phase 6D3 does not rebuild automatically.

After an ambiguous send, blockhash expiry does **not** erase submission history and is
not permission to rebuild or resend. The transaction may already have landed.

A later phase/policy may permit a new attempt only when the prior attempt is proven safe
for replacement.

## RPC boundary and preflight

The Phase 6D3 RPC surface adds only:

- exact raw-transaction submission;
- one-signature status lookup.

The generic solana-py client stays private.

Because Phase 6D2 already simulates the exact signed bytes with signature verification,
Phase 6D3 calls `sendRawTransaction` with RPC preflight explicitly skipped. solana-py
local confirmation is disabled and RPC node `maxRetries` is set to zero. Confirmation
is owned explicitly by the transaction-attempt reconciliation state machine.

There is no multi-RPC failover.

## Commitment policy

The configured Phase 6D2/6D3 commitment is explicit. Confirmation levels are ordered:

```
processed < confirmed < finalized
```

`processed` is not treated as `confirmed` unless runtime policy explicitly requests
`processed`. Public-devnet should use its repository-configured commitment (normally
`confirmed`).

A Solana/program error observed only below the required commitment remains `PENDING`
with the error preserved. It becomes `FAILED_FINAL` only when that same transaction
status reaches the configured commitment. A confirmed landed failure never returns to
a ready-to-submit state.

## Durable protocol state remains unchanged

Submission and reconciliation do not mutate:

- coordinator `AGREED`/`CONFLICT` history;
- verifier A/B results;
- resolver/evidence identity;
- signing intents or anti-equivocation state;
- signer epochs;
- completed A/B 2/2 signatures.

The execution journal exclusively owns blockchain submission status.

## Real solders compatibility

Transaction bytes, `Hash`, `Signature`, `VersionedTransaction`, local signature
verification, and transaction parsing use the repository-pinned `solders==0.20.0`.
There is no shim path.

## Explicitly outside Phase 6D3

Phase 6D3 does not implement:

- coordinator-to-submit automation;
- background submission/confirmation workers;
- infinite confirmation polling;
- blind retry/rebroadcast after ambiguous send;
- multi-RPC fallback;
- automatic stale-blockhash rebuild policy;
- a public settlement submission HTTP endpoint;
- mainnet execution behavior;
- final product-level settlement reconciliation beyond the durable transaction result.

Most importantly: **a transport timeout is not proof that a transaction was not
submitted.**
