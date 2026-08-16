# Resolver V2 settlement simulation (Phase 6D2)

Phase 6D2 extends the completed deterministic Phase 6D1 settlement transaction builder with exactly three transaction-lifecycle operations: trusted recent-blockhash acquisition, dedicated fee-payer transaction signing, and Solana RPC simulation. It does **not** submit or broadcast a transaction.

## Security boundary

Resolution authorization and Solana transaction authorization are separate identities.

- **Resolution authorization:** the already-durable Vault signer A + signer B Ed25519 signatures over the exact existing `PROPHET_RESOLVE_V2` bytes.
- **Transaction authorization / fee payment:** one dedicated Solana fee-payer keypair that signs the Solana transaction message only.

The fee payer is not a Prophet resolution notary. It is not appended to `PROPHET_RESOLVE_V2`, cannot replace A or B, does not influence the outcome, and is not part of the 2/2 resolution policy. Phase 6D2 additionally rejects a fee-payer public key that equals either durable resolution signer public key.

## Runtime configuration

The optional Resolver Runtime Configuration section is:

```yaml
settlement_execution:
  rpc_url_env: PROPHET_DEVNET_RPC_URL
  expected_cluster: devnet
  expected_genesis_hash: <canonical Solana genesis hash>
  fee_payer:
    keypair_path_env: PROPHET_DEVNET_FEE_PAYER_KEYPAIR_PATH
  rpc:
    timeout_seconds: 10
    commitment: confirmed
```

`expected_cluster` and `expected_genesis_hash` must exactly match the existing validated `solana` runtime identity. The RPC URL and fee-payer path are environment references rather than inline credentials/private material. Existing runtime fingerprints are unchanged when `settlement_execution` is absent; when present, only the non-secret environment references and execution policy are fingerprinted.

Phase 6D2 does not introduce mainnet execution behavior.

## Fee-payer key loading

Production/public-devnet fee-payer signing uses `FilesystemFeePayerSigner`. The path is resolved from the configured environment-variable name. The file must exist and contain exactly one Solana CLI-style JSON array of 64 integer bytes (`0..255`).

The loader rejects:

- 32-byte seeds;
- base58 private strings;
- seed phrases;
- inline private-key runtime fields;
- malformed/ambiguous JSON encodings;
- unresolved or missing files.

Private bytes are retained only inside the signer object and are never placed in application result objects or log fields.

## RPC trust and genesis validation

`SolanaSettlementRpcClient` exposes only:

1. `getGenesisHash`
2. `getLatestBlockhash`
3. `simulateTransaction`

There is no application-level `sendTransaction`, `sendRawTransaction`, or confirmation API in Phase 6D2.

Every execution attempt validates the RPC-reported genesis hash against the configured expected genesis hash before acquiring a blockhash. A mismatch fails closed and performs no blockhash acquisition, transaction signing, or simulation. There is no fallback RPC or cluster switching.

Credential-bearing RPC URLs are not emitted by this layer. The safe endpoint label contains only the host (and port when present).

## Recent blockhash acquisition

The execution layer obtains the recent blockhash from the already genesis-validated RPC. The RPC result is parsed through real `solders==0.20.0` `Hash` construction and must round-trip canonically.

Callers of `SettlementSimulationService.simulate()` provide only:

- coordinator job ID;
- signing intent ID.

They cannot provide or override the recent blockhash, market, outcome, resolver identity, A/B signatures, or canonical settlement message.

Phase 6D2 performs no blockhash refresh loop. If simulation reports a stale/invalid blockhash, the result is `STALE_BLOCKHASH` and execution stops.

## Reuse of Phase 6D1

After genesis validation and blockhash acquisition, Phase 6D2 calls the existing `SettlementTransactionBuilder` with:

- the durable coordinator job ID;
- the durable signing intent ID;
- the dedicated fee-payer public key;
- the fresh RPC blockhash.

Therefore the transaction contains exactly the Phase 6D1 instruction sequence:

1. native Ed25519 verification instruction for durable signer A;
2. native Ed25519 verification instruction for durable signer B;
3. existing Prophet `resolve_market_threshold` instruction.

Phase 6D2 does not rebuild the settlement instruction, change account metas, add compute-budget instructions, introduce ALTs, or change `PROPHET_RESOLVE_V2`.

## PROPHET_RESOLVE_V2 invariance

Fee-payer signing is performed after deterministic construction. The canonical settlement bytes, canonical digest, A signature, and B signature are captured and asserted unchanged across fee-payer signing.

Changing the fee payer or recent blockhash changes the Solana transaction/message as expected, but does not change the durable resolution authorization bundle.

## Transaction signing

The Phase 6D1 `MessageV0` is required to have exactly one transaction-level signer, with the dedicated fee payer as the first required account. Resolution signer A/B signatures remain data inside native Ed25519 verification instructions and their private keys are not required for transaction signing.

The fee payer creates a real `solders==0.20.0` `VersionedTransaction`. Phase 6D2 locally checks the transaction signature with `verify_with_results()` / `verify_and_hash_message()` and verifies serialization round-trip before simulation.

The immutable signed artifact contains safe fields including coordinator/signing IDs, runtime identity, fee-payer public key, recent blockhash, canonical settlement digest/bytes, A/B public signature references, the Phase 6D1 unsigned artifact, serialized transaction bytes, transaction signature strings, and a transaction digest. It contains no private key material.

## Simulation

The exact `VersionedTransaction` object whose serialized bytes are returned in the signed artifact is passed to `simulateTransaction` with signature verification enabled and recent-blockhash replacement disabled.

Safe simulation result fields include:

- readiness state;
- program error, if any;
- program logs;
- compute units consumed when returned;
- replacement blockhash diagnostics when returned by RPC.

Simulation states are:

- `READY_CANDIDATE`: simulation returned no program error. This means only that the candidate simulated successfully; it is **not confirmed or settled**.
- `PROGRAM_REJECTED`: simulation returned a program/transaction error.
- `STALE_BLOCKHASH`: simulation reported blockhash-not-found/stale behavior.

Transport failures, malformed RPC responses, invalid local transaction signatures, or runtime/RPC binding mismatches raise typed fail-closed errors. They never cause implicit fallback, repair, resigning, or submission.

## Durable state remains unchanged

Phase 6D2 is read-only with respect to protocol durable state. It does not mutate:

- coordinator jobs or verifier results;
- `AGREED` / `CONFLICT` state;
- settlement contexts/runtime bindings;
- signing intents or coordinator-signing links;
- the completed A/B signature bundle.

It also performs zero new Vault signing calls and has no verifier dependency.

## No broadcast

Phase 6D2 stops after simulation. It does not call or expose a settlement execution path for:

- `sendTransaction`;
- `sendRawTransaction`;
- confirmation polling;
- automatic rebroadcast/retry;
- coordinator auto-submit;
- settlement reconciliation.

## Phase 6D3 remaining work

Phase 6D3 or later must define, separately:

- transaction submission;
- durable submitted-signature/result persistence;
- confirmation handling;
- restart reconciliation;
- stale-blockhash rebuild/re-sign policy;
- rebroadcast/idempotency policy;
- final settlement reconciliation.
