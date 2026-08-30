# RC4.4 fixed-role settlement boundary

The generic remote signer, direct attester settlement, and same-process A+B
quorum are retired. The operated production manifests launch resolver-registry,
verifier A, verifier B, coordinator, matching keeper, and monitoring only.

Settlement authority is split before credential acquisition:

1. fixed-role signer A independently validates P0C1 and consumes its own
   role-local admission grant and replay journal;
2. fixed-role signer B independently performs the same work in its own process,
   with its own RPC trust, Vault policy, and P0C2 journal;
3. a public raw-signature bridge validates the ordered A/B signatures over the
   existing `PROPHET_RESOLVE_V2` message;
4. the local fee payer submits the three-instruction Solana transaction.

The coordinator, submitter, broker, and recovery tooling receive no signer
private material or Vault credentials. A process or operator session must never
possess both role credentials. Cross-role grants and replayed grants reject
before P0C1; ambiguous P0C2 signing remains `UNCERTAIN` and is never retried
automatically.

The localtest proof is `make operated-smoke`. It starts an ephemeral loopback
validator when needed, preloads the frozen program at genesis, proves finalized
chain reads and on-chain settlement, and cleans up its child processes. It is
not a public deployment path. Public-devnet remains paused and mainnet remains
blocked.
