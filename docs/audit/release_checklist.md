# Release and audit handoff checklist

All items require an accountable owner and dated evidence before a public
testnet launch. A checkbox is not evidence by itself.

- [ ] CI green at immutable revision; `cargo test --workspace --locked`, `anchor build`, `make demo`, and security commands reproduced.
- [ ] ABI/protocol surface frozen; IDL, program artifact, resolver vectors, and SDK version hashes recorded.
- [ ] Audit package reviewed for completeness; external audit scope accepted.
- [ ] No unresolved critical or high findings; lower-severity accepted risks have owners and dates.
- [ ] Dedicated testnet deployment authority, market authority, resolver operator, and signer keys verified; no developer/CI key reuse.
- [ ] Key rotation and signer-config version-change drill completed; Vault access reviewed.
- [ ] Testnet deployment verified with exact cluster domain, registry, 2/2 signer policy, rate limits, and artifact hashes.
- [ ] Monitoring live; all required alert routes and response owners tested.
- [ ] Backup/restore and rollback rehearsed; audit/evidence retention verified.
- [ ] Public demo executed without credentials or operator secrets; conflict demo visibly fails closed.
- [ ] External audit findings are closed, explicitly accepted, or block release according to severity policy.
