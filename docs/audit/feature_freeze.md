# Prophet v1.0.0-rc1 feature-freeze policy

Feature development is frozen at `Prophet v1.0.0-rc1` until independent
security audit completion and release approval. Permitted changes are security
or correctness fixes, tests, documentation, CI/release mechanics, and audited
finding remediation. They must include regression coverage, an ABI impact
statement, and release-lead approval.

New protocol functionality, resolver adapters, tokenomics, economic changes,
new instruction semantics, account-layout changes, and API redesigns are
prohibited. Any proposed exception creates a new release candidate and resets
the ABI/audit baseline review.
