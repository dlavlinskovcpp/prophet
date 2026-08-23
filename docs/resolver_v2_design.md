# Resolver V2 Design

**Status:** architecture proposal; no protocol changes are implied by this document.

## Executive decision

Adopt **architecture B: independent verifier implementations plus threshold
attestations** as the target Resolver V2 architecture. Keep the current
threshold-attestation settlement path for existing markets and use it as the
settlement adapter during V2.0 and V2.1. Move narrowly useful, stable checks
on-chain only in V3, beginning with native Solana data sources such as Pyth and
appropriately constrained Chainlink feeds where the compute and account model
are acceptable.

This produces a useful separation of concerns:

```text
Resolver definition -> evidence acquisition -> verification -> evaluation
                    -> independent attestations -> on-chain settlement
```

No component may silently combine these responsibilities. In particular, an
HTTP fetcher is not a verifier, a verifier is not a signer, and a signer does
not decide an outcome from a URL.

## Goals and non-goals

Resolver V2 provides deterministic, versioned resolver definitions; pluggable
resolver adapters; durable evidence and verification records; explicit trust
models; and a compatible path for existing `resolver_hash` markets.

It does not make arbitrary web data trustless, make off-chain liveness
censorship-resistant, or allow mutable resolver logic to rewrite the meaning of
an existing market. A hash is an identifier, not proof that a source is honest.

## 1. Resolver interface

Every resolver adapter implements the following logical interface. The names
describe an interface contract, not a required programming language API.

```text
validate(definition) -> ValidatedDefinition | ValidationError
acquire(definition, acquisition_context) -> EvidenceEnvelope | AcquisitionError
verify(definition, evidence, verification_context) -> VerificationResult
evaluate(definition, verification_result) -> ResolverDecision
```

`validate` is pure and must reject ambiguous configuration before publication.
`acquire` may use the network or a chain RPC, but records exactly what it used.
`verify` validates authenticity, freshness, provenance, and schema conformance;
it must not fetch replacement data. `evaluate` is pure and maps verified facts to
`YES`, `NO`, `INVALID`, or `NO_RESULT`.

`NO_RESULT` is deliberately not an on-chain market outcome. It means insufficient
verified evidence, a timeout, or an unresolved conflict. It prevents an outage
from being accidentally interpreted as `NO`.

Each adapter publishes immutable metadata:

```text
adapter_id          e.g. prophet.resolver.pyth
adapter_version     semantic version of the implementation contract
schema_id           e.g. prophet.resolver-definition.v2
capabilities        supported sources, proofs, predicates, finality models
trust_model_id      immutable named trust-model document/hash
implementation_id   source release digest or reproducible artifact digest
```

Adapters are allowlisted by the operated resolver registry. A custom adapter is
not executable configuration: it must be a separately reviewed and versioned
adapter artifact, with its digest included in the definition.

## 2. ResolverDefinition schema

ResolverDefinition V2 is a typed, canonical JSON document using RFC 8785 JSON
Canonicalization Scheme (JCS). It prohibits IEEE-754 JSON numbers for economic
or comparison values: quantities and timestamps are decimal strings or typed
integer fields. Unicode strings are normalized to NFC before JCS serialization.

```json
{
  "schema": "prophet.resolver-definition.v2",
  "schema_version": "2.0.0",
  "resolver_type": "pyth",
  "adapter": {
    "id": "prophet.resolver.pyth",
    "version": "2.0.0",
    "implementation_digest": "sha256:<32-byte-hex>"
  },
  "trust_model": {
    "id": "pyth-solana-finalized.v1",
    "document_hash": "sha256:<32-byte-hex>"
  },
  "source": {},
  "verification_policy": {},
  "evaluation": {},
  "timing": {
    "not_before": "2026-08-15T00:00:00Z",
    "observation_deadline": "2026-08-16T00:00:00Z",
    "max_evidence_age_seconds": "300"
  },
  "conflict_policy": {},
  "fallback_policy": {}
}
```

Required common rules:

- `schema`, `resolver_type`, adapter identity/version/digest, and trust-model
  identity/hash are mandatory.
- `source`, `verification_policy`, and `evaluation` are resolver-type-specific
  typed objects, not unvalidated blobs.
- Each hostname, URL, chain ID, feed ID, public key, TLS pin, aggregation rule,
  timeout, and exact comparison semantics is explicit.
- `additionalProperties: false` is required at every schema level. Unknown
  fields are rejected, never ignored.
- A definition must name its finality model. “latest” is invalid.
- The definition is immutable once referenced by a market. Any semantic change,
  including an adapter implementation change, creates a new definition hash.

### Resolver-type profiles

| Type | `source` and verification requirements | Primary trust boundary |
| --- | --- | --- |
| `zktls` | URL/method/request commitment, expected server identity, circuit/proof system and verifier digest, response extraction path, proof public-input schema. | TLS endpoint, proof system/circuit and verifier implementation. |
| `http_api` | Exact URL, method, request body hash, required headers, DNS policy, TLS SPKI pins or authenticated provider signature keys, response schema and JSON pointer. Plain HTTPS without a provenance mechanism is explicitly a trusted-provider mode. | API operator, DNS/TLS policy, acquisition infrastructure. |
| `pyth` | Solana cluster genesis hash, program ID, price-account address, exponent/price/confidence predicates, publisher/guardian/finality policy and slot age. | Pyth governance/publishers and the selected Solana finality assumption. |
| `chainlink` | Source-chain CAIP-2 ID, aggregator address, round fields, decimals, heartbeat, minimum confirmations, RPC quorum policy, and optional finalized block hash. | Chainlink feed governance/operators, source-chain finality, RPC quorum. |
| `signed_oracle` | Oracle key set, signature scheme, threshold, message schema/domain, sequence/nonce policy, TTL and key-set version. | Oracle key holders and their threshold. |
| `custom` | Reviewed adapter ID/version/implementation digest plus an adapter-specific schema. It cannot use an unspecified URL or executable expression. | The custom adapter’s explicit trust model. |

For comparisons, the definition uses a typed expression vocabulary such as
`decimal_gte`, `integer_eq`, `bytes_eq`, and `enum_in`. Free-form predicates,
JavaScript, JSONPath extensions, locale-sensitive parsing, and floating-point
comparisons are prohibited.

## 3. `resolver_hash` derivation

Resolver V2 uses a domain-separated identity hash:

```text
resolver_hash_v2 = SHA-256(
  "PROPHET_RESOLVER_DEFINITION_V2\x00" ||
  u16_le(schema_name_length) || schema_name_utf8 ||
  canonical_jcs_definition_bytes
)
```

`schema_name` is `prophet.resolver-definition.v2`. The schema name is included
outside the JSON so an accidental legacy JSON hash can never collide by
convention with a V2 identity. The registry stores the canonical bytes, hash,
validation report, publication time, signer/auditor records, and adapter digest.

### Compatibility rule

Existing markets retain their current `resolver_hash` meaning exactly: SHA-256
of sorted compact legacy JSON, as documented in `docs/resolver_spec.md`. They
are **legacy resolver schema v1** markets. Resolver V2 services select the hash
algorithm by market resolver profile; they do not reinterpret a legacy hash as a
V2 definition.

New markets may use a V2 hash in the existing 32-byte `market.resolver_hash`
field without changing the trading protocol. The registry is the source of the
schema/profile selection until V3 introduces optional on-chain resolver metadata.

## 4. Versioning rules

There are four independently versioned objects:

1. **Definition schema:** major changes are incompatible and require a new
   `schema` identifier. A minor version may add an optional field only when its
   default is explicitly canonical and semantically inert; otherwise use a new
   definition schema major.
2. **Adapter contract:** semantic version in the definition. A change to parsing,
   verification, dependencies, finality interpretation, or evaluation behavior
   is a new adapter version and new implementation digest.
3. **Trust model:** versioned document plus content hash. A change to who or what
   is trusted is never a documentation-only change.
4. **Attestation wire format:** a distinct, domain-separated version. Existing
   `PROPHET_RESOLVE_V2` messages remain valid only for existing settlement.

Definitions are content-addressed and never edited in place. Registry aliases
such as `btc-usd-pyth-latest` are convenience pointers only and may not be used
by a market definition or signer policy.

## 5. Evidence format

Evidence is a binary canonical CBOR (`dCBOR`) envelope. Canonical CBOR prevents
signature/hash ambiguity for arbitrary bytes and is appropriate for proofs,
headers, account data, and signed observations. Maps use integer keys; fields
that contain JSON include the exact canonical JCS bytes and their hash.

```text
EvidenceEnvelopeV2 {
  format: "prophet.evidence.v2",
  definition_hash: bytes32,
  evidence_id: bytes32,                 // SHA-256 of canonical envelope
  acquisition_id: bytes16,              // random unique request ID
  acquired_at_unix_ms: u64,
  source_time_unix_ms: u64 | null,
  source_sequence: bytes | null,
  source_locator: typed locator,
  source_commitment: bytes32,           // URL/request/account/round commitment
  payload: bytes,
  payload_hash: bytes32,
  provenance: typed proof/signature/finality material,
  transport: typed TLS/DNS/RPC metadata,
  collector: { implementation_digest, instance_id },
  previous_evidence_hash: bytes32 | null
}
```

The evidence format stores raw inputs needed for independent replay, subject to
redaction policy. Secrets and authorization headers are never stored; their
presence is represented by a redacted field commitment. Evidence must be
immutable in content-addressed storage with an auditable retention policy.

## 6. Verification result format

Verification is deterministic over a definition and an evidence envelope.

```text
VerificationResultV2 {
  format: "prophet.verification-result.v2",
  definition_hash: bytes32,
  evidence_hash: bytes32,
  verifier: { id, version, implementation_digest },
  result: VERIFIED | REJECTED | INCONCLUSIVE,
  checks: [
    { check_id, status, expected_commitment, observed_commitment, detail_hash }
  ],
  verified_facts: canonical-CBOR bytes,
  verified_facts_hash: bytes32,
  observed_at_unix_ms: u64,
  valid_from_unix_ms: u64,
  valid_until_unix_ms: u64,
  finality: typed finality assertion | null,
  result_hash: bytes32
}
```

Only `VERIFIED` results may reach evaluation. `REJECTED` means the evidence
failed a specified check; `INCONCLUSIVE` means it did not establish the fact.
Neither one is automatically an Invalid market.

`ResolverDecision` is the pure output of evaluation:

```text
{ decision: YES | NO | INVALID | NO_RESULT,
  reason_code: enum,
  definition_hash: bytes32,
  verification_result_hashes: [bytes32],
  evaluated_at_unix_ms: u64 }
```

## 7. Attestation message format

### Resolver V2 evidence attestation

Each independent verifier/notary signs a canonical message before its result is
eligible for threshold aggregation:

```text
domain                 "PROPHET_RESOLVER_ATTEST_V2\x00"
cluster_genesis_hash   32 bytes
settlement_program_id  32 bytes
market                 32 bytes
resolver_hash          32 bytes
definition_hash        32 bytes (must equal resolver_hash for V2 markets)
adapter_digest          32 bytes
trust_model_hash        32 bytes
notary_config           32 bytes
notary_config_version   u64 little-endian
decision                u8 (YES=1, NO=2, INVALID=3, NO_RESULT=4)
evidence_bundle_hash    32 bytes
verification_bundle_hash 32 bytes
observed_at_unix_ms     u64 little-endian
valid_until_unix_ms     u64 little-endian
resolution_nonce        32 bytes
```

The signature scheme is Ed25519 unless the signer policy explicitly introduces
a separately versioned scheme. Signers must sign only after independently
recomputing the definition hash, verification result hash, and decision.

### Current-market settlement adapter

Current markets and the existing on-chain handler must continue to use the
unchanged `PROPHET_RESOLVE_V2` message documented in
`docs/attestation_format.md`. For those markets, Resolver V2 creates a canonical
`ResolutionBundleV2` from the evidence and verification result; its digest is
committed through the existing `proof_hash` and `public_inputs_hash` fields.
Threshold signers sign the current on-chain message only after reviewing the
Resolver V2 bundle. This preserves byte-for-byte on-chain compatibility and
improves off-chain auditability without claiming that the current program parses
the new envelope.

V3 markets can verify the full Resolver V2 attestation format directly after a
new, explicitly versioned settlement instruction is introduced.

## 8–9. Replay protection and domain separation

Replay protection is layered rather than relying on a timestamp alone:

- The attestation binds cluster genesis hash, settlement program ID, market key,
  resolver hash, notary configuration key/version, and a unique nonce.
- `resolution_nonce = SHA-256("PROPHET_RESOLUTION_NONCE_V2\x00" || market ||
  resolver_hash || resolve_ts_le || evidence_bundle_hash)`.
- Evidence binds its definition hash, exact source commitment, payload hash, and
  acquisition ID. Signed-oracle evidence also binds oracle key-set version and
  monotonic source sequence.
- Verification results bind both the evidence and verifier implementation digest.
- Attestation expiry is enforced by signer policy. A stale, otherwise valid
  result cannot be newly attested after `valid_until`.
- Every serialized object has a unique ASCII domain tag ending in `\x00`; hashes
  and signatures never share a domain.

The current on-chain message already binds program, market, resolver hash,
schedule, configuration version, outcome, and hashes. Resolver V2 preserves
those bindings for legacy settlement and adds explicit cluster binding to the
off-chain evidence attestation.

## 10–11. Threshold signer model and rotation

The threshold set is a policy boundary, not merely a collection of equivalent
keys. Each signer has a declared role and independence class:

```text
signer_id, public_key, keyset_version, role,
operator, implementation_digest, independence_class, permitted_resolver_types
```

Production policy should require a threshold across at least two independence
classes where possible (for example, a zkTLS verifier operated separately from
a chain-data verifier). A threshold of multiple keys under one operator is key
redundancy, not independent verification.

Rotation is two-phase:

1. Publish and audit a new signed key-set version with an activation time;
   retain the old set for verification/audit.
2. For new markets, bind the new version at market creation. Existing markets
   retain the on-chain `NotaryConfig` semantics and version binding already
   present in `PROPHET_RESOLVE_V2`.

An emergency revocation may disable a key for future attestations. It cannot
retroactively invalidate an already settled market. Rotation events, signer
policy decisions, and rejected signing attempts are append-only audit records.

## 12–13. Resolver upgrades and deprecation

Definitions are immutable. “Upgrade” means publishing a new definition hash and
using it only for a new market, or—only if a future market explicitly opts into
resolver migration—performing a governed on-chain migration with a new schedule
and fresh participant notice. Default rule: **no resolver upgrade for a live
market**.

Deprecation is registry metadata, not mutation. A deprecated definition remains
retrievable with its canonical bytes and validation records. New market creation
must reject deprecated schemas, adapters, or trust models after their effective
date. Existing markets retain support until resolved, but operators must publish
a deterministic end-of-support and fallback plan.

## 14–16. Failure, conflict, and Invalid behavior

### Failure and timeout

The definition specifies an observation deadline, evidence TTL, verification
deadline, minimum independent verified results, and a terminal fallback policy.
Until the policy is satisfied, the resolver returns `NO_RESULT`; no signer may
convert it to a market outcome. This distinguishes a data-provider outage from a
negative answer.

At timeout, the policy may permit one of these explicit actions:

1. **Continue pending:** market remains unresolved; operational escalation only.
2. **Threshold Invalid:** an independently verified timeout condition plus the
   configured signer threshold produces `INVALID`.
3. **Threshold Invalid:** an explicit policy-approved `INVALID` outcome still
   requires the market's pinned on-chain threshold authorization; there is no
   authority settlement fallback.

There is no automatic `YES` or `NO` on timeout.

### Conflicting evidence

Evidence is not “majority averaged” by default. A definition must select one
conflict policy:

- `single_authoritative_source`: conflicting secondary evidence is audit signal;
  it cannot override a verified canonical source.
- `quorum_identical_fact`: at least N independent verifiers must produce the
  same typed fact and source epoch.
- `median_numeric`: an explicitly named set of feeds, exact normalization,
  minimum count, maximum spread, and deterministic median tie rule.
- `fail_invalid`: any verified contradiction inside a defined observation window
  leads to threshold `INVALID`.
- `fail_no_result`: conflict blocks settlement until human/governed escalation.

The definition must state which evidence is authoritative and whether a conflict
is a source failure, a verifier disagreement, or an Invalid condition.

### Invalid-market fallback

`INVALID` is appropriate when the market question cannot be resolved according
to its immutable policy—for example malformed authoritative data, an explicit
source retraction, a verifier-proven contradictory state under `fail_invalid`,
or a configured timeout fallback proved by the required threshold. It is not a
catch-all for operational inconvenience. Invalid payout behavior remains the
existing protocol behavior and is outside Resolver V2.

## Threat model and mitigations

| Threat | Primary control | Residual assumption |
| --- | --- | --- |
| Malicious resolver definition | Strict schema, immutable hash, registry review, market UI displays exact definition/trust model. | Market creator can still choose a bad but explicit source. |
| Compromised attester | Separate acquisition/verifier/signer roles; signer recomputation; independent implementations and audit bundles. | A compromised threshold of signers can resolve falsely. |
| Compromised threshold signers | Independent operators/classes, HSM/KMS, rate limits, rotation/revocation, signed decision logs. | Threshold keys remain the final authorization boundary. |
| Stale evidence | Source sequence/slot/block and explicit TTL/finality policy; signer rejects expired result. | Source timestamps and chain finality model are accurate. |
| Replayed evidence | Market/cluster/program/config/nonce binding and content-addressed envelope chain. | V3 must enforce the new nonce on-chain; legacy path relies on existing terminal state plus bindings. |
| Cross-market or cross-cluster replay | Market key, program ID, cluster genesis hash, resolver hash, schedule, and config version in signed material. | Correct cluster genesis configuration at verifier startup. |
| DNS/API manipulation | TLS SPKI pins or provider signatures, request commitment, resolver allowlist, multi-vantage acquisition. | Pinned endpoint/provider can itself lie. |
| Definition ambiguity | JCS/dCBOR, no unknown fields/floats/free-form code, typed comparisons, fixed adapter digest. | Canonicalization implementations must be independently tested. |
| Signer censorship | Multiple operators, retry queues, public attestation status, timeout policy. | Resolver V2 does not guarantee liveness. |
| Signer equivocation | Append-only signed decision logs; same market/nonce may have at most one decision per signer; monitoring and revocation. | Detection does not undo a settled threshold decision. |

## Architecture comparison

| Dimension | A. Current threshold attestation | B. Independent verifiers + threshold | C. Native/on-chain proof verification |
| --- | --- | --- | --- |
| Trust assumptions | Threshold signers and operated attester correctly acquire and evaluate evidence. | Threshold is still trusted for final authorization, but independent implementations/operators reduce common-mode verifier failure. | Trust shifts toward proof system, verifier circuit/program, source update mechanism, and Solana execution; external data provenance may still be trusted. |
| Compute cost | Low: Ed25519/message verification and hash storage. | Low on-chain; higher off-chain acquisition and verification cost. | Potentially high or impractical for zkTLS/general proofs; native feeds can be modest. |
| Operational complexity | Lowest. | High: registry, evidence store, multiple implementations, signer policy, discrepancy monitoring. | High protocol/audit burden; proof generation/verification operations may be substantial. |
| Failure modes | Attester/signers can be wrong, censored, stale, or share a common bug. | Disagreement and liveness complexity; a common specification bug can still affect all implementations. | Verifier bugs, compute limits, account/finality issues, proof availability, expensive upgrades. |
| Decentralization | Limited by signer/operator set. | Better when verifier/signer operators and implementations are genuinely independent. | Strongest for verifiable native data, but only where proofs/data are practically on-chain. |
| Auditability | Hashes and signer identities; raw evidence depends on operator retention. | Strong: immutable evidence, verification reports, implementation digests, and signed decision logs. | Strong for executed verifier logic and inputs; external input provenance remains contextual. |
| Upgradeability | Current program/config upgrades; risk if off-chain semantics drift. | Immutable definitions/adapters, new hashes for changes, clear registry lifecycle. | Requires program/circuit upgrades and migration; highest compatibility risk. |

### Recommendation

Use **B** as the default, retain **A** as the legacy settlement compatibility
adapter, and use **C selectively** for sources with a mature native verification
path. Do not attempt generic on-chain zkTLS verification as a prerequisite for
Resolver V2; it would concentrate complexity and consume compute without solving
every source-provenance problem.

## Staged roadmap

### V2.0 — deterministic resolver framework, no core protocol change

1. Publish the ResolverDefinition V2 schemas, JCS/dCBOR test vectors, hash
   derivation specification, and schema validator.
2. Build an immutable resolver registry with definition publication, adapter and
   trust-model digest records, deprecation metadata, and audit export.
3. Split the attester pipeline into acquisition, verification, evaluation, and
   signing-policy modules; emit `EvidenceEnvelopeV2`, `VerificationResultV2`,
   and `ResolutionBundleV2`.
4. Implement zkTLS, signed-oracle, and strictly pinned HTTP/API adapters first.
   Implement Pyth and Chainlink adapters as read/verify adapters with explicit
   chain finality/RPC quorum policies.
5. Bind all final current-market submissions through the unchanged
   `PROPHET_RESOLVE_V2` message using ResolutionBundle V2 hashes. Add replay and
   canonicalization vectors plus independent verifier regression tests.

### V2.1 — independence and operations

1. Add at least two independent verifier implementations for the highest-value
   resolver types, with separate operators or isolation domains.
2. Add threshold signing policy enforcement: allowed resolver types, adapter
   digest allowlists, evidence expiry, decision/nonce uniqueness, and signer
   equivocation logs.
3. Add conflict-policy execution, deterministic timeout reports, multi-vantage
   HTTP acquisition, RPC quorum support, and public resolution status/audit APIs.
4. Establish external review requirements for custom adapters and a reproducible
   conformance suite all adapters must pass.

### V3 — opt-in on-chain resolver commitments

1. Introduce a new market/resolution version only; never reinterpret V2 markets.
2. Add an on-chain resolver-profile/config commitment and a V3 resolution
   message that binds Resolver V2 definition, evidence, verification, nonce,
   cluster, and expiry fields directly.
3. Add narrowly scoped native verification for feasible data sources—first
   finalized Solana Pyth account checks, then carefully bounded Chainlink/source
   adapters where a native trust model is auditable.
4. Consider on-chain timeout/Invalid policy enforcement only after governance,
   account-size, compute, and migration reviews. Keep generic zkTLS proof
   verification off-chain unless a dedicated feasibility and audit effort proves
   it safe and affordable.

## Migration from the current resolver system

1. Classify every existing market as legacy resolver schema v1; use the existing
   sorted-JSON SHA-256 derivation and current threshold message unchanged.
2. Import legacy definitions as immutable registry records with a `legacy-v1`
   profile. Do not canonicalize and re-hash them as V2.
3. Run Resolver V2 acquisition/verification in shadow mode for legacy markets.
   Compare its generated bundle hashes and decisions against the currently
   operated path before enabling it to request signatures.
4. For new V2.0 markets, store `resolver_hash_v2` in the existing market hash
   field and settle through the current threshold handler with a V2 bundle
   commitment. This is backward compatible at the core trading layer.
5. Create V3 markets only after V3 resolution instruction and account schema are
   audited and deployed. Existing markets remain resolvable through their
   original version forever.

## Components to implement first

In order:

1. Canonical ResolverDefinition V2 schemas, validation library, JCS/dCBOR
   vectors, and `resolver_hash_v2` library shared by SDK, registry, attester, and
   independent test implementation.
2. Immutable registry records for definition, adapter digest, trust-model hash,
   lifecycle status, and audit retrieval.
3. Evidence/verification/result bundle formats plus content-addressed storage
   and replay tooling.
4. Attester pipeline separation and signer policy engine that independently
   validates bundle commitments before signing the existing settlement message.
5. zkTLS, signed oracle, and pinned HTTP/API adapters; then Pyth and Chainlink
   adapters with finalized-data and quorum policies.
6. A second independent verifier implementation, conformance tests, conflict
   handling, and signer equivocation monitoring.

Only after those components have operated in shadow mode and received review
should V3 on-chain resolver commitments or native verifier paths be proposed.
