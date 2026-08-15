# Agent-native E2E Demo

Run the deterministic fixture demo from a checkout with the attester Poetry
environment installed:

```sh
make demo
```

It prints two machine-readable JSON documents: a successful Pyth-fixture
resolution and an intentional verifier-conflict result. The command fails on
any unexpected stage failure. It needs no RPC endpoint, wallet, secret, or
public oracle endpoint. The fixture uses fixed keys, timestamps, feed binding,
and account bytes, so its logical output is reproducible. The separate
operated-localnet smoke test continues to cover actual transaction submission.

## Lifecycle

`ProphetAgent` is the agent-facing facade. An agent passes a question and an
explicit `ResolverConfig`, then calls `buy_yes`, `buy_no`, `match_orders`,
`resolve`, and `redeem`. The facade hides PDA derivation, instruction layouts,
token accounts, and signature framing. Resolver ID, definition, required
verifier set, and signer threshold remain explicit security configuration.

The successful fixture creates a market identity/PDA, crosses 100 YES and NO
orders, constructs canonical Pyth evidence, verifies it with the primary and
independent implementations, requires 2/2 agreement, creates threshold
signatures, and constructs the byte-for-byte existing
`PROPHET_RESOLVE_V2` settlement message. The deterministic local submission
receipt is the SHA-256 commitment of those exact legacy bytes; it is not a
network transaction. No protocol semantics are changed.

The conflict fixture injects `YES` from verifier one and `NO` from verifier
two. It emits `state: "conflicted"`, `conflict_persisted: true`, and null
signer/settlement fields. It cannot proceed to authorization or submission.

## JSON contract

Each line is one JSON object with `market_id`, `market_pda`, orders, match
receipt, `evidence_hash`, verifier identities, agreement decision,
`resolution_bundle_hash`, threshold result, settlement receipt, and redemption
amount. No secrets or private key material are included.

## Developer experience review

An agent developer writes roughly 5–10 lines: construct `ResolverConfig`,
create a market, place two intents, resolve, and redeem. PDAs, ATAs, order
sequence numbers, instruction accounts, ed25519 framing, and raw transaction
construction no longer leak through the facade.

The remaining mandatory concepts are intentional: a resolver definition,
trusted feed/network binding, verifier identities, freshness policy, and
threshold policy. Autonomous agents can use the API safely when they select
these policy values from an approved configuration rather than inventing them
at runtime. A production transaction backend may be injected behind the same
`AgentBackend` protocol; the deterministic demo deliberately does not grant
the fixture a wallet or network authority.
