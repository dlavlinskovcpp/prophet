# Trust-boundary map

| Boundary | Trusted property | Malicious/failure behavior | Detection | Recovery |
|---|---|---|---|---|
| User wallet | Signs its own intents | Fraudulent orders, lost key | On-chain authority/signature checks, events | User key rotation; cancel before fill where allowed |
| Solana program | Deployed audited binary | Bug or unauthorized upgrade | ABI hash, CI, program inspection | Freeze/rollback upgrade authority; pause operational path |
| Quote vault | Token program custody and PDA ownership | Bad account substitution, token-program failure | Account/mint/authority validation; balance reconciliation | Halt operations; investigate and restore only by governed release |
| Fee vault/accounting | Accrued-fee accounting | Invalid recipient/withdrawal request | Token account validation, fee invariants, alerts | Authority correction before first order; incident review |
| Market authority | Authorized lifecycle/config action | Compromised authority | Transaction/event monitoring | Transfer authority; emergency INVALID where permitted |
| Resolver registry | Immutable definition metadata | Bad/deprecated entry/operator outage | Hash binding, audit records, registry monitoring | Deprecate/replace resolver; use approved fresh definition |
| Evidence source | Correct underlying fact | API/DNS/oracle manipulation or outage | Proof/signature/feed binding, freshness checks | Fresh source evidence or INVALID fallback per policy |
| Verifier #1 / #2 | Correct independent verification | Bug, stale cache, equivocation | Canonical results, agreement policy, conflict store | Fresh evidence, approved override, implementation rollback |
| Threshold signer | Signs only authorized legacy bytes | Key compromise/censorship/equivocation | Policy, allowlist, equivocation monitor, audit logs | Rotate notary config/version; recollect signatures |
| Vault Transit | HSM-backed key isolation | Transit outage/key misuse | Vault audit logs, signer metrics, allowlist | Key rotation, fail closed, alternate approved notaries |
| RPC provider | Availability and accurate transport | Censorship, stale/reorged view | Multi-RPC operational checks, confirmations | Fail over RPC; wait finality; do not bypass bindings |
| Keeper | Honest matching submission availability | Censorship/bug | Order events, keeper metrics, user permissionless paths | Restart/replace keeper; users may submit valid calls |
| Oracle attester | Correct pipeline orchestration | Compromise/outage | Structured audit, policy, verifier agreement | Rebuild/redeploy reviewed image; no automatic policy bypass |
| SDK/agent layer | Correct client-side intent construction | Malicious UI/agent config | Explicit resolver/policy inputs, deterministic demo | Revoke credentials; use independently verified SDK/version |
