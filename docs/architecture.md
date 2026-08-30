# Prophet Architecture

Prophet is a Solana prediction-market protocol for autonomous agents. The
Solana program owns financial state and final authorization; Resolver V2 and
its off-chain services supply machine-readable resolution evidence.

## System map

```mermaid
flowchart LR
    A[Agents / traders] --> SDK[Python SDK / agent facade]
    SDK --> P[Prophet Solana program]
    K[Matching keeper<br/>(off-chain policy)] --> P

    P -. resolver_hash .-> R[Resolver V2 registry<br/>canonical definition]
    R --> VA[Verifier A]
    R --> VB[Verifier B]

    VA --> IA[Admission issuer A]
    VB --> IB[Admission issuer B]
    IA --> SA[Fixed-role Signer A]
    IB --> SB[Fixed-role Signer B]

    RA[RPC trust domain A] --> SA
    RB[RPC trust domain B] --> SB
    VLA[Vault / key domain A] <--> SA
    VLB[Vault / key domain B] <--> SB

    C[Credential-free coordinator / broker<br/>cache only] --> VA
    C --> VB
    SA --> C
    SB --> C
    C --> X[Permissionless submitter]
    X --> P
    M[Monitoring / durable operational state] -.-> C
    M -.-> SA
    M -.-> SB
```

The production boundary is fixed before credentials are acquired:

> No production process can possess or accept both Signer A and Signer B
> credentials.

Signer A and Signer B are separate processes with role-local runtime identity,
admission authority, Vault access, finalized-RPC trust, replay journals, and
anti-equivocation state. The diagram is deliberately not a generic signer
topology.

## Authority by layer

| Layer | Authority | Responsibility |
| --- | --- | --- |
| Solana program | Consensus-enforced | Custody, order accounting, matching arithmetic, fees, refunds, redemption, lifecycle, notary snapshot binding, and final settlement authorization |
| Resolver V2 | Commitment and validation format | Canonical machine-readable resolution definition and `resolver_hash` binding |
| Verifier A/B | Off-chain evidence verification | Independently evaluate evidence and authenticate the result; they do not settle funds |
| Signer A/B | Off-chain authorization | Independently validate finalized chain context, G1/G2/P0C1/P0C2 policy, and authorize the canonical settlement message |
| Coordinator/broker | Non-authoritative coordination | Queue, cache, and route untrusted work; it has no signer credentials and is not an authorization authority |
| Matching keeper | Off-chain matching policy | Discover crossed orders and submit caller-selected valid `match_orders` transactions |
| SDK / agents / relayers | Clients | Create markets, trade, operate workflows, and submit permissionless transactions |

## Market V2 and settlement

Every Market V2 input must contain a non-zero `resolver_hash` and an exact
2-of-2 `NotaryConfig` with two distinct non-zero notary keys. A generic
N-of-M account representation may exist for protocol evolution, but unsupported
topologies are rejected by the current Market V2 path.

Resolution follows this sequence:

1. The market commits to a canonical Resolver V2 definition by hash.
2. Verifier A and Verifier B evaluate the evidence independently.
3. Each role-local signer validates admission G1, durable replay state G2,
   independent P0C1 authorization, and P0C2 anti-equivocation state.
4. Signer A and Signer B sign the identical `PROPHET_RESOLVE_V2` message.
   The current message is exactly 235 bytes.
5. A credential-free submitter places the Ed25519 instructions and
   `resolve_market_threshold` in a permissionless transaction.
6. The Solana program verifies the canonical bytes, distinct threshold
   signatures, and immutable market snapshot before changing state.

The chain verifies settlement authorization and stores the outcome,
`proof_hash`, and `public_inputs_hash`. It does not verify zkTLS proofs itself.

## Matching semantics

Prophet V1 uses **permissionless limit-order crossing**. A caller selects a
valid opposite-side pair; the program checks market membership, price
crossing, ownership constraints, and accounting invariants. The matching keeper
uses best-price / earliest-order policy as an off-chain convenience.

The protocol does not consensus-enforce a global top of book, global best
execution, strict price priority, strict time priority, or Sybil-resistant
self-trade prevention. Prophet V1 should therefore not be described as a
strict CLOB without that qualification.

## Runtime endpoints and state

`/live` reports process liveness. `/ready` is dependency-aware and fail-closed;
it checks real dependencies without producing a settlement signature. Before
the first public-devnet program deployment, a correct runtime may report
`expected_program_missing` for settlement readiness. That is not a reason to
weaken the readiness check.

Role-local durable state includes G2 replay data, P0C2 anti-equivocation data,
signing journals, and transaction-attempt reconciliation state. A coordinator
database is only a broker/cache store. It must not contain signer credentials,
issuer private keys, or authorization authority.

## Deployment shapes

### Deterministic demo

`make demo` runs the repository's deterministic agent-native Resolver V2 demo,
including agreement and conflict fail-closed paths. It uses local fixtures and
does not deploy or require a wallet.

### Localtest fixed-role topology

`make operated-smoke` exercises two fixed-role signer services through an
ephemeral localtest environment. Its keys and infrastructure are developer
fixtures, not evidence of production administrative independence.

### Operated public-devnet

The checked-in operated topology uses Resolver V2 registry, Verifier A,
Verifier B, credential-free coordinator, matching keeper, monitoring, and two
independent fixed-role signer domains. Real Vault, RPC, issuer, TLS, durable
storage, and alerting infrastructure must be provisioned outside the
repository. Public-devnet is currently paused; the Prophet program is not
deployed there.

### Mainnet future gate

Mainnet remains blocked. An external independent audit is required before
significant mainnet TVL, in addition to live operational evidence, deployment
authorization, monitoring, recovery drills, and an approved liveness/key-loss
plan.

## Read next

- Protocol and economic semantics: [`protocol.md`](protocol.md)
- Trust assumptions and security boundaries: [`trust_model.md`](trust_model.md)
- Developer flow: [`devnet_quickstart.md`](devnet_quickstart.md)
- Python SDK: [`sdk_quickstart.md`](sdk_quickstart.md)
- Resolver V2 schema: [`resolver_spec.md`](resolver_spec.md)
- Operations and recovery: [`ops_runbook.md`](ops_runbook.md)
- External audit scope: [`security_review_scope.md`](security_review_scope.md)
