# RC4.6 Authoritative Backlog

These items are deliberately deferred and are not consensus guarantees in
RC4.6. Each item requires a new acceptance revision before production use.

| Item | Safety implication | Public-devnet gate | Mainnet gate |
| --- | --- | --- | --- |
| Strict CLOB / global best execution / on-chain fair matching | Current V1 permits any valid crossing pair; no fairness or priority guarantee | Keep disabled; operated keeper policy only | New protocol architecture, adversarial tests, and audit |
| Economic identity, Sybil resistance, and wash-trade prevention | Exact wallet self-match rejection is not economic-identity protection | No incentives | Anti-abuse design, monitoring, and audit |
| More than exact 2-of-2 Market V2 notaries | Larger topologies are not accepted by the current Market V2 initializer | Reject | New account/transaction capacity review and audit |
| External resolver implementations | Unknown definitions are not operated-supported | Keeper allowlist only | Resolver review, verifier implementation, and audit |
| Automated production deployment | RC4.6 does not authorize deployment | PAUSED | BLOCKED pending release approval |

Every deferred item must carry a safety consequence, a devnet enablement
condition, and a mainnet release gate in its next acceptance basis.
