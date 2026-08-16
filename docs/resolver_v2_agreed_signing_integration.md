# Resolver V2 AGREED → 2-of-2 signing integration

Phase 6C5 adds one explicit in-process application boundary:

```python
settlement_signer.sign_agreed_job(job_id)
```

It converts one already durable coordinator `AGREED` job into one durable strict Vault 2-of-2 signature bundle. The output is settlement-signing evidence only. This phase does not construct or submit a Solana transaction.

## Durable AGREED prerequisite

`AGREED` is the only signable coordinator state. `PENDING`, one-verifier partial states, `CONFLICT`, unknown jobs, and malformed historical records fail before signing-intent creation or any Vault signing call. The caller cannot supply or override outcome, market, resolver identity, verifier results, evidence digest, or canonical message digest through the signing boundary.

The coordinator job and its persisted verifier A/B results remain authoritative and read-only during signing. The integration revalidates their resolver/evidence/verifier bindings and reuses the existing exact 2-of-2 agreement policy before constructing settlement bytes.

## Durable settlement context

The legacy `PROPHET_RESOLVE_V2` message contains protocol fields that were not previously present in the coordinator job row: program ID, notary config, open/resolve timestamps, notary config version, proof hash, and public-inputs hash.

Phase 6C5 stores those non-result inputs in an immutable `resolution_job_settlement_contexts` sidecar keyed by coordinator job ID. The context must be bound while the job is still `PENDING`, before either verifier result is persisted. An exact repeated binding is idempotent; a different binding or a late first binding is rejected.

Market, resolver hash, and outcome are deliberately not duplicated in that context. They are always loaded from the durable coordinator job when signing begins.

## Canonical settlement derivation

The signing path is:

```text
durable AGREED coordinator job
        +
immutable durable settlement context
        ↓
existing build_legacy_settlement_message(...)
        ↓
exact PROPHET_RESOLVE_V2 canonical bytes
```

No serializer is added. No coordinator job ID, signing-journal ID, Vault metadata, runtime fingerprint, service URL, correlation ID, or other operational field is appended to the protocol message.

The coordinator's 32-byte hex market identifier is converted to the same Solana public-key bytes before calling the existing builder. The resolver hash and outcome come directly from the durable AGREED job.

## Coordinator → signing linkage

`SigningJournal` keeps a durable `coordinator_signing_links` sidecar:

```text
coordinator_job_id → signing_scope_id + canonical_message_digest
```

The coordinator job ID is provenance only. It is not the cryptographic signing identity. The existing `settlement_signing_scope(canonical_message)` remains the authoritative anti-equivocation scope.

Signing-intent creation and coordinator linkage occur in the same signing-journal SQLite transaction. A repeated exact job/message reuses the existing intent. The same coordinator job cannot be rebound to a different scope or digest.

## Intent creation, idempotency, and key-version pinning

`ThresholdResolutionSigner.prepare_2_of_2(...)` performs the durable pre-Vault phase. It creates or loads the existing journal intent and commits:

- canonical signing scope;
- canonical message digest and exact bytes;
- signer A identity/public key/key version;
- signer B identity/public key/key version;
- coordinator-job provenance linkage.

For a new intent, the existing epoch-selection policy chooses A/B epochs at intent creation. For an existing intent, the persisted epochs are rehydrated with `for_pinned_epoch`; active/latest keys are never reselected.

`sign_agreed_job` then calls the existing recovery-aware strict 2-of-2 signer. It does not reimplement threshold, signature-validation, anti-equivocation, or recovery semantics.

## Restart and recovery

Existing signing-journal states remain authoritative:

- no signature recorded: continue through the existing durable-before-Vault sequence;
- A durable, B not started: reuse A and call only B;
- A or B marked signing with no durable result: return the explicit recovery-required/fail-closed error and do not broaden retries;
- both signatures durable: return the same immutable completed bundle and make zero Vault signing calls.

A process restart reopens SQLite state and preserves the coordinator linkage, exact canonical bytes, and pinned signer epochs.

## Conflict and partial jobs

A durable coordinator `CONFLICT` is permanently non-signable through this boundary, even if each individual verifier result is syntactically valid. Partial jobs are also non-signable; agreement is never inferred early.

Both cases fail before creation of a signing intent and before any Vault signing call.

## Result

The application result contains only public/safe signing evidence:

- coordinator job ID;
- signing intent/scope ID;
- durable signing state;
- canonical message digest and exact canonical settlement bytes;
- signer A public identity and pinned key version;
- signer B public identity and pinned key version;
- completed strict 2-of-2 signature bundle.

Vault tokens, Authorization headers, and private material are never returned.

## Explicit boundary; no automatic signing

`ResolutionCoordinator.resolve()` remains a coordination operation only. Reaching `AGREED` does not automatically sign. Phase 6C5 intentionally requires the separate explicit in-process call to `sign_agreed_job(job_id)`.

No `/sign`, `/settle`, or `/submit` HTTP endpoint is added.

## No Solana transaction construction/submission

Phase 6C5 stops at exact canonical `PROPHET_RESOLVE_V2` bytes plus two valid durable Ed25519 signatures. It does not:

- create Solana settlement instructions;
- build or submit a transaction;
- perform RPC submission or confirmation;
- pay transaction fees;
- add queues, retry workers, background signers, or Docker orchestration.
