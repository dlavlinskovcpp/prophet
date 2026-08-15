# Accepted residual-risk register

| Risk | Status | Mitigation / residual exposure |
|---|---|---|
| Threshold signer compromise | requires external audit | Threshold, explicit policy, Vault/allowlists; quorum compromise can resolve incorrectly |
| Correlated verifier failure | requires external audit | Independent parsers and 2/2 policy; shared schemas/sources remain correlated |
| RPC censorship or stale RPC | accepted | Failover and confirmation monitoring; availability is not guaranteed |
| Source/API manipulation | mitigated | Source binding, proofs/signatures/feed identity; source truth remains external trust |
| Stale oracle evidence | mitigated | Explicit freshness limits and rejection metrics |
| Key compromise | requires external audit | Dedicated keys, rotation, config versioning; response time is operational |
| Signer availability failure | accepted | Fail closed; liveness depends on sufficient available signers |
| Registry/operator compromise | mitigated | Immutable entries and hash binding; approved governance/operator path remains trusted |
| Chain reorg/finality assumptions | accepted | Confirmation/finality procedures; deep reorgs can delay operational conclusions |
| Liquidity/manipulation risk | accepted | Protocol matches valid orders; it does not guarantee fair market price |
| Sybil/order-slot economics | deferred | Per-user/global limits help; economic tuning needs public testnet data |
| Persistent account rent costs | accepted | Documented account allocations; users bear normal Solana rent economics |
| Cross-cluster replay assumptions | mitigated | Cluster/domain bindings in V2 evidence and resolution policy |
| Upgrade authority compromise | requires external audit | Dedicated authority and release controls required before public deployment |

## Explicit limitations

The program is not formally verified. Resolver registry operators, market
authorities, threshold signers, Vault Transit operators, RPC providers, and
third-party oracle/proof systems are trusted or operationally privileged at
their documented boundary. Multi-verifier diversity reduces implementation
risk but does not make evidence sources decentralized. Public-devnet service
availability and alert delivery depend on deployed off-chain infrastructure.
Further decentralization, formal methods, and any deferred V3 work are not
part of this RC.
