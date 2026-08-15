# Questions for independent auditors

Please challenge, rather than assume, the following:

1. Are custody, escrow, fee, refund, redemption, and INVALID payout invariants complete under all instruction orderings?
2. Can matching arithmetic, rounding, partial fills, or fee fragmentation create value or liabilities?
3. Can arbitrary accounts, token accounts, authorities, or PDAs be substituted?
4. Are PDA seed derivations and account constraints complete for every instruction?
5. Do threshold signer, Vault, authority, and upgrade trust assumptions match actual enforcement?
6. Can independent verifiers still fail correlatively through formats, source dependencies, policy, or implementation reuse?
7. Are Resolver V2 canonicalization, hash/domain separation, and legacy compatibility unambiguous across implementations?
8. Can evidence, bundles, signatures, or signed-oracle messages replay across markets, resolvers, versions, or clusters?
9. Do signer/verifier equivocation protections prevent issuance before conflicting state is detected?
10. Are oracle freshness, confidence, feed, timestamp, and round assumptions safe at boundaries?
11. Does INVALID payout conservation survive arbitrary redemption order and maximum values?
12. Is emergency/governance authority appropriately constrained, auditable, and recoverable?
13. Is upgrade-authority compromise adequately mitigated operationally?
