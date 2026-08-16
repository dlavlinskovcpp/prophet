# Resolver V2 settlement transaction construction

Phase 6D1 defines the explicit, network-free boundary between a completed durable
Resolver V2 settlement signature bundle and a Solana transaction message that is
ready for a later execution/submission phase.

It does **not** submit, simulate, sign with a production fee payer, fetch a
blockhash, confirm, reconcile, retry, or rebroadcast a transaction.

## Authoritative durable inputs

The application entry point is `SettlementTransactionBuilder.build()` with a
`SettlementTransactionInput` containing only:

- durable coordinator job ID;
- expected durable signing-intent ID;
- fee-payer public key;
- caller/runtime-supplied recent blockhash.

Market, resolver identity, outcome, notary configuration, canonical settlement
bytes, signer identities/epochs, and signatures are not request fields. They are
loaded from the existing coordinator state and signing journal.

Only a durable coordinator job whose current state is `AGREED` and whose linked
signing intent is durably `BOTH_SIGNED` can be constructed. `CONFLICT`, partial,
missing, uncertain, malformed, or incorrectly linked history fails closed.
Construction never invokes signing.

## Durable Solana runtime binding

Phase 6D1 adds an immutable `SettlementRuntimeBinding` sidecar to coordinator
state containing:

- cluster;
- genesis hash;
- Prophet program ID.

It is bound before verifier progress, just like the existing immutable settlement
message context. It is operational/cross-cluster provenance only and is **not**
added to `PROPHET_RESOLVE_V2`. Existing historical jobs without this provenance
are non-constructible rather than being retroactively bound to whichever runtime
happens to build them later.

The transaction builder requires the sidecar to match the validated
`SolanaRuntimeConfig` byte-for-byte and also requires its program ID to match the
program ID already present in the durable settlement context.

## Exact `PROPHET_RESOLVE_V2` reuse

The signing journal's durable `canonical_message` is the authoritative byte
string fed to both Ed25519 verification instructions. The builder does not create
an alternative settlement serializer.

As a fail-closed compatibility assertion, it derives the expected bytes through
the same existing Phase 6C settlement-message builder and requires:

- byte-for-byte equality with the durable journal bytes; and
- SHA-256 equality with the durable canonical-message digest.

Changing fee payer or recent blockhash cannot change these bytes or the durable
2/2 resolution signatures.

## Existing Ed25519 instruction builder

Both signature-verification instructions use the existing
`prophet_sdk.ed25519.build_ed25519_ix` builder. No new signature wire format or
verification mechanism is introduced.

The A/B order is the persisted protocol/runtime role order:

1. signer A Ed25519 verification;
2. signer B Ed25519 verification;
3. Prophet `resolve_market_threshold` instruction.

The builder never sorts by public key, Vault key name, dictionary order, or
completion time.

Before instruction construction, the completed journal record is locally
revalidated. `SigningJournal.validate_completed_intent()` rechecks its durable
slot bindings, message digest, signature size, and Ed25519 signatures. The
existing `ThresholdResolutionSigner` additionally exposes a network-free durable
bundle validation path that rehydrates the exact configured historical A/B key
epochs and validates role, public key, key version, digest, and signatures. It
performs no Vault metadata lookup and no Vault signing call.

## Existing Prophet settlement instruction contract

Phase 6D1 preserves the current Anchor/client contract without IDL or program
changes.

Instruction: `resolve_market_threshold(outcome, proof_hash, public_inputs_hash)`.

Instruction arguments are the existing layout:

- Anchor discriminator: first 8 bytes of
  `sha256("global:resolve_market_threshold")`;
- outcome: one `u8` (`YES=1`, `NO=2`, `INVALID=3`);
- `proof_hash`: 32 bytes;
- `public_inputs_hash`: 32 bytes.

Accounts, in order:

1. `market` — writable, non-signer;
2. `notary_config` — read-only, non-signer;
3. instructions sysvar — read-only, non-signer.

The market PDA is re-derived using the existing Python SDK PDA helper from
`resolver_definition_hash`, `open_ts`, and the runtime-bound Prophet program ID.
A mismatch fails closed. Notary configuration and notary configuration version
come from the durable settlement context and are bound to the signed canonical
message by the byte-equality check.

The on-chain instruction scans preceding native Ed25519 instructions for the
exact expected settlement message and counts distinct authorized notary
signatures. Phase 6D1 therefore emits A then B Ed25519 instructions before the
Prophet instruction and does not insert unrelated instructions between them.

The pure `build_resolve_threshold_instruction()` boundary is a network-free
adapter over the existing `SolanaClient.build_resolve_threshold_ix()` method. It
bypasses `SolanaClient.__init__` so it does not construct an RPC client or load
keypairs, then invokes that existing instruction builder unchanged. Phase 6D1
therefore does not maintain a second settlement-instruction encoding, and the
legacy RPC client file itself is not modified.

## Transaction representation

Phase 6D1 returns an **unsigned `solders.message.MessageV0` artifact** plus its
serialized message bytes. This preserves the current client path, which already
uses `MessageV0`, while avoiding production fee-payer secret handling.

No address lookup tables are supplied and no compute-budget instructions are
added, matching the current settlement path.

The immutable application artifact contains safe public material:

- coordinator job ID and signing-intent ID;
- program/cluster/genesis identity;
- fee-payer public key and recent blockhash;
- ordered instructions;
- exact canonical settlement bytes and digest;
- signer A/B public identities, pinned versions, and signatures;
- `MessageV0`, serialized message bytes, and message SHA-256 digest.

It contains no private key, seed phrase, Vault token, authorization header, or
production transaction-signing capability.

## Fee-payer boundary

The fee payer is a Solana transaction-lifecycle role, not settlement
authorization. It is not appended to `PROPHET_RESOLVE_V2`, cannot replace signer
A/B, cannot alter outcome/resolver/notary identity, and does not change the
resolution signatures.

Phase 6D1 accepts only its public key. It intentionally does not load a fee-payer
private key or ask the Vault resolution signers to sign the Solana transaction.
Role separation is enforced by data flow: the fee payer never supplies or replaces
the durable A/B resolution signatures, even if a test happens to reuse a public key.

## Recent blockhash boundary

The recent blockhash is caller/runtime supplied. Phase 6D1 performs no RPC lookup.
Changing it changes the serialized Solana transaction message, as expected, but
does not alter `PROPHET_RESOLVE_V2` or either resolution signature.

## Determinism and read-only behavior

For fixed durable state, program/runtime identity, fee-payer public key, and
recent blockhash, repeated construction produces byte-identical serialized
`MessageV0` bytes and the same message digest.

Construction is read-only:

- zero Vault metadata calls;
- zero Vault signing calls;
- zero verifier calls;
- zero Solana RPC calls;
- zero coordinator mutations;
- zero signing-journal mutations.

## `solders==0.20.0`

The application dependency is pinned to `solders==0.20.0`. The construction path
uses its real `Pubkey`, `Signature`, `Instruction`, `AccountMeta`, `Hash`, and
`MessageV0` types. The Prophet SDK is used directly for the existing Ed25519 and
market-PDA helpers.

## Outside Phase 6D1

The following remain intentionally unimplemented:

- recent blockhash acquisition;
- production fee-payer signing/private-key management;
- simulation;
- RPC transaction submission;
- confirmation and settlement reconciliation;
- retry, rebroadcast, or blockhash-refresh loops;
- automatic submission from coordinator/signing completion;
- background workers or queues.
