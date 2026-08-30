# RC4.6 External Audit Package Index

This release candidate is a package for external review, not a claim that an
external audit has occurred. The package scope is:

- on-chain Market V2 exact 2-of-2 admission, lifecycle, matching arithmetic,
  escrow accounting, and threshold settlement;
- the permissionless limit-order crossing semantics and explicit non-guarantees;
- Resolver V2 canonical parsing, hash binding, runtime adapter allowlists, and
  operated preflight;
- fixed-role signer admission, readiness, durable replay journals, bounded
  concurrency, and Vault identity binding;
- matching-keeper private operations, health dimensions, discovery filtering,
  production configuration, and safe logging;
- acceptance manifests, immutable cryptographic vectors, production image
  scans, and clean remote revalidation evidence.

Known limitations are recorded in
`docs/audit/rc4_6_consistency_backlog.md`. An independent external audit remains
required before mainnet use or significant TVL. No audit result is implied by
this release candidate.
