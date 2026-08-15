# Resolver V2.0 Canonical Format Specification

This is an off-chain format only. It does not change legacy resolver hashes,
market accounts, or the `PROPHET_RESOLVE_V2` settlement message.

## Canonical JSON

All V2 payloads are UTF-8 JSON objects with these rules:

- Object keys are ASCII snake_case (`[a-z][a-z0-9_]*`) and sort by ASCII byte.
- Strings must already be Unicode NFC. Decomposed strings are rejected.
- JSON numbers, including integer literals and floats, are forbidden. Unsigned
  integers and timestamps are canonical ASCII decimal strings (`0|[1-9][0-9]*`)
  within `u64`.
- Bytes and digests are lowercase hexadecimal; a digest is exactly 64 hex digits.
- Arrays preserve their supplied order. Set-like arrays have schema-defined
  ordering and reject duplicates.
- Every optional field is present and uses `null` when empty. There are no
  hash-affecting implicit defaults.
- Serialization is compact JSON: sorted keys, `,` and `:` separators, no
  whitespace, and UTF-8 strings with standard JSON escaping.

## Schema headers

Every payload has exact `schema` and `schema_version` fields. V2.0 supports
only version `2.0.0`.

| Object | Schema |
| --- | --- |
| AdapterDescriptorV2 | `prophet.adapter-descriptor.v2` |
| TrustModelDescriptorV2 | `prophet.trust-model-descriptor.v2` |
| ResolverDefinitionV2 | `prophet.resolver-definition.v2` |
| EvidenceEnvelopeV2 | `prophet.evidence-envelope.v2` |
| VerificationResultV2 | `prophet.verification-result.v2` |
| ResolutionBundleV2 | `prophet.resolution-bundle.v2` |
| RegistryEntryV2 | `prophet.resolver-registry-entry.v2` |

Unknown or missing fixed-schema fields are rejected. Adapter-specific policy and
provenance objects still use canonical JSON and cannot contain executable code.

## Exact payload fields

All fields listed below are required unless their value is explicitly `null`.
Nested policy/provenance values are canonical JSON objects with documented
application-specific keys; no nested field can acquire a hash-affecting default.

| Object | Exact top-level fields |
| --- | --- |
| AdapterDescriptorV2 | `schema`, `schema_version`, `adapter_id`, `adapter_version`, `implementation_digest` |
| TrustModelDescriptorV2 | `schema`, `schema_version`, `trust_model_id`, `trust_model_version`, `document_hash` |
| ResolverDefinitionV2 | `schema`, `schema_version`, `resolver_id`, `resolver_type`, `adapter`, `trust_model`, `source`, `verification_policy`, `evaluation`, `timing`, `conflict_policy`, `fallback_policy` |
| EvidenceEnvelopeV2 | `schema`, `schema_version`, `evidence_id`, `definition_hash`, `source_locator`, `source_commitment`, `payload_hex`, `payload_hash`, `provenance`, `transport`, `collector`, `acquisition_id`, `source_sequence`, `source_time_ms`, `acquired_at_ms`, `previous_evidence_hash` |
| VerificationResultV2 | `schema`, `schema_version`, `definition_hash`, `evidence_hash`, `verifier`, `checks`, `verified_facts_hex`, `verified_facts_hash`, `result`, `valid_from_ms`, `valid_until_ms`, `observed_at_ms`, `finality` |
| ResolutionBundleV2 | `schema`, `schema_version`, `market`, `resolver_definition`, `resolver_definition_hash`, `evidence`, `verification_results`, `trust_model`, `trust_model_digest`, `verifier`, `signer_policy`, `outcome`, `observed_at_ms`, `valid_until_ms`, `cluster_genesis_hash`, `settlement_program_id`, `notary_config`, `notary_config_version`, `resolution_nonce` |

All timestamp and sequence fields are u64 decimal strings. `payload_hash` must
equal SHA-256 of the bytes represented by `payload_hex`, and
`verified_facts_hash` must equal SHA-256 of `verified_facts_hex` bytes.

## Hash byte layout

Every component hash is SHA-256 over exactly:

```text
domain_tag                         ASCII bytes, including trailing 0x00
u16_le(schema byte length)
schema                             ASCII bytes
u16_le(schema_version byte length)
schema_version                     ASCII bytes
u32_le(canonical_payload length)
canonical_payload                  canonical UTF-8 JSON bytes
```

| Function | Domain tag |
| --- | --- |
| `adapter_digest` | `PROPHET_ADAPTER_DESCRIPTOR_V2\0` |
| `trust_model_digest` | `PROPHET_TRUST_MODEL_V2\0` |
| `resolver_definition_hash` | `PROPHET_RESOLVER_DEFINITION_V2\0` |
| `evidence_hash` | `PROPHET_EVIDENCE_ENVELOPE_V2\0` |
| `verification_result_hash` | `PROPHET_VERIFICATION_RESULT_V2\0` |
| `resolution_bundle_hash` | `PROPHET_RESOLUTION_BUNDLE_V2\0` |

The domain tag, schema, and version are inputs to every hash. A V2 bundle hash
therefore cannot be a legacy resolver hash, even for identical application JSON.

## Object bindings

- AdapterDescriptorV2: adapter ID/version and implementation digest.
- TrustModelDescriptorV2: trust-model ID/version and document hash.
- ResolverDefinitionV2: resolver ID/type, adapter, trust model, source,
  verification/evaluation policy, timing, conflict, and fallback policy.
- EvidenceEnvelopeV2: definition, source/request, payload, provenance,
  transport, collector, sequence, timestamps, and chain linkage.
- VerificationResultV2: definition/evidence, verifier identity, check/fact
  commitments, validity interval, and finality record.
- ResolutionBundleV2: market, full definition, evidence/results, trust/verifier,
  signer policy, outcome, times, cluster/program/notary domain, and nonce.

Bundle validation rejects hash/binding mismatch, duplicate evidence IDs,
unordered verification results, stale evidence, and inconsistent timestamps.

## Immutable registry

RegistryEntryV2 binds resolver ID, definition hash, adapter/trust-model digests,
schema version, creation time, and explicit nullable deprecation fields. Entries
are immutable. A deprecation is a separate record bound to the original entry
digest; it never changes definition bytes or substitutes a live market resolver.

## Legacy compatibility

Legacy resolver definitions remain SHA-256 of sorted compact JSON exactly as in
`docs/resolver_spec.md`. V2 does not parse or change `PROPHET_RESOLVE_V2`.
