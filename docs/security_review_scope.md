# External Security Review Scope

This document is the handoff scope for an independent security and adversarial
review of Prophet V1. Internal CI and security acceptance are regression
evidence; they are not a substitute for this external audit.

## Release context

The current release candidate is `v1.0.0-rc4.7` at commit
`42351960cae1497d1a0e5dfebf46d65a72c4c5db`. Its acceptance basis is revision 6
with digest
`a7f3d1a2ee4b6377a7bfc26cc4ef93e01e559a08d3f1bf4482fe323875b2ad9d`, and CI
run `33339208482` is green.

Public-devnet is paused and the Prophet program is not deployed there. Mainnet
is blocked. An external independent audit is required before significant
mainnet TVL.

Generate a review bundle with a current release tag or a generic tag:

```bash
make security-review-bundle ENV=devnet TAG=<release-tag>
```

The generated package and remediation workflow are described in
[`security_review_process.md`](security_review_process.md).

## In-scope components

### On-chain

- market lifecycle and authority boundaries;
- order placement, matching arithmetic, custody, fees, and refunds;
- redemption and payout accounting;
- exact 2-of-2 Market V2 binding and immutable notary snapshots;
- canonical `PROPHET_RESOLVE_V2` message construction;
- Ed25519 instruction parsing and threshold resolve verification; and
- account sizing, rent, limits, and failure behavior.

### Off-chain

- Resolver V2 canonicalization, hashing, registry, and operated support policy;
- verifier attestations and independent Verifier A/B agreement;
- G1 admission and durable G2 replay protection;
- independent P0C1 authorization and P0C2 anti-equivocation;
- fixed-role Signer A and Signer B processes and credential boundaries;
- Vault identity, key-version binding, audit, and non-exportability;
- independent finalized-RPC trust paths;
- credential-free coordinator/broker and its compromise boundary;
- matching keeper discovery, matching policy, durable state, and ops boundary;
- transaction construction, simulation, submission, and reconciliation; and
- operational evidence, signed package authority, restart, recovery, and
  deployment topology.

## Core properties to verify

- No production process can possess or accept both Signer A and Signer B
  credentials.
- No generic, role-selectable, or same-process A+B signer is a production launch
  surface.
- A Market V2 input has a non-zero resolver hash and exact 2-of-2 notary keys.
- Signer A and Signer B authorize the identical 235-byte settlement message.
- Replay, cross-role grants, stale state, ambiguity, and equivocation fail closed.
- The coordinator, submitter, matching keeper, and resolver registry cannot
  directly authorize settlement or mint signer credentials.
- The chain remains the authority for custody, accounting, lifecycle, and final
  signature verification.

## Review questions

### Protocol and matching

- Are custody, fees, refunds, redemption, and lifecycle transitions correct
  under malformed, concurrent, and adversarial inputs?
- Does exact 2-of-2 Market V2 binding remain immutable for an existing market?
- Is matching correctly documented and enforced as permissionless limit-order
  crossing rather than consensus global price-time priority?
- Is there any unintended Sybil or self-trade assumption?

### Resolver and evidence

- Can a resolver be spoofed, substituted, reordered, or interpreted under a
  different canonical hash?
- Are verifier attestations bound to the market, resolver, evidence, outcome,
  timestamps, and trust model?
- Does verifier disagreement or stale/unsupported evidence fail closed?
- Is it clear that zkTLS verification is off-chain and not a chain guarantee?

### Authorization and signer isolation

- Can a coordinator compromise induce a signer authorization without satisfying
  G1, G2, P0C1, and P0C2?
- Can a signer equivocate, replay a grant, accept a cross-role grant, or sign
  after uncertain durable state?
- Can any process, filesystem principal, recovery path, or operator session
  obtain both role credentials or issuer private keys?
- Are Vault identities, key versions, audit records, and public-key bindings
  correctly proven for both roles?
- Can compromise of one signer or its RPC corrupt both signers' worldview?

### Operations and deployment

- Are RPC A/B domains genuinely independent and finalized-state checks sound?
- Are journals durable, distinct, restart-safe, backed up, and restored without
  losing replay or anti-equivocation history?
- Are package freshness, artifact hashes, release identity, and signed
  operational evidence bound to the intended deployment?
- Are TLS, private ingress, metrics, alerting, rate limits, and secret surfaces
  correctly isolated?
- What are the failure and liveness consequences of losing one pinned 2-of-2
  key, and is the operator recovery policy honest about that limitation?
- Can deployment topology accidentally start a retired signer path, accept a
  generic backend, or reuse local/test credentials?

## Explicit non-goals and assumptions

The current system does not claim:

- on-chain zkTLS proof verification;
- fully trustless external-data resolution;
- global consensus best execution or strict price-time matching;
- Sybil-resistant economic identity;
- guaranteed off-chain verifier, signer, Vault, registry, or RPC liveness; or
- an emergency market-authority resolution or Invalid bypass.

The review should identify assumptions that are stronger than these stated
boundaries, especially assumptions about external evidence, operator honesty,
RPC correctness, key custody, and availability.

## Evidence package

Reviewers should receive, with secrets redacted but identities and hashes
preserved:

- the release program artifact, IDL, types, and manifest;
- source revision and immutable acceptance-basis digest;
- Resolver V2 definitions, canonical hashes, and expected outcomes;
- verifier attestations and positive/negative test vectors;
- G1/G2/P0C1/P0C2 evidence and fixed-role A/B public bindings;
- Vault provenance, key versions, RPC trust-domain records, and TLS topology;
- coordinator, keeper, registry, monitoring, backup, recovery, and deployment
  configurations; and
- test results, known-risk register, incident procedures, and remediation log.

Do not include private keys, Vault root or development tokens, issuer private
keys, or unredacted operator credentials in the review bundle.
