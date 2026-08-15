# Resolver V2 zkTLS Adapter

The zkTLS adapter is an evidence producer and independent-verifier client. It
does not import a signer or Solana client and cannot submit settlement.

## Definition profile

The V2 definition has `resolver_type: "zktls"` and a `source` object with
exactly: `source_domain`, `request_definition_hash`, `response_selector`,
`predicate`, `response_schema`, `response_schema_version`, `proof_version`,
`cluster_genesis_hash`, and `max_evidence_age_ms`. All identifiers and hashes
are committed in the resolver-definition hash.

Evidence contains canonical JSON holding the proof bytes, response bytes, proof
version, source domain, request-definition hash, and cluster genesis hash. The
generic `EvidenceEnvelopeV2` then commits to those bytes and the acquisition
metadata. No HTTP fallback or unspecified selector is allowed.

## Verification

`ZkTlsProofVerifier` is implementation-neutral: it returns only validity and
claims for proof version, source domain, request commitment, cluster, and
response hash. A second verifier can implement this same interface without
altering evidence bytes.

The adapter rejects invalid proofs, unsupported versions, source/request or
cluster mismatch, resolver/adapter/trust-model mismatch, stale evidence,
response schema mismatch, malformed JSON, missing selectors, and failed
predicates. It emits a canonical rejected `VerificationResultV2` with a stable
failure code; rejected results cannot be signed by the V2 pipeline.

## Trust assumptions and test vectors

Trust rests on the selected proof verifier implementation/circuit and the
resolver definition's exact source/request constraints. Test fixtures cover a
valid proof plus invalid proof, wrong domain, wrong selector, stale evidence,
malformed response, resolver mismatch, adapter mismatch, trust mismatch, and
unsupported proof version. Proofs, response bodies, credentials, and sessions
are not included in signer authorization or audit records.
