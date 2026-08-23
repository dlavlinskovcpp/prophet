# Resolver V2 verifier attestations

`PROPHET_VERIFIER_ATTESTATION_V1` is an off-chain Ed25519 certificate emitted
by verifier A or verifier B after a `VERIFIED` Resolver V2 result. It does not
alter `PROPHET_RESOLVE_V2`, its 235-byte settlement message, or any on-chain
account or instruction format.

The payload has exactly these fields: `attestation_schema`,
`attestation_version`, `verifier_id`, `verifier_version`,
`verifier_implementation_digest`, `job_id`, `cluster_genesis_hash`,
`program_id`, `market`, `resolver_definition_hash`, `evidence_hash`,
`outcome`, `proof_hash`, `public_inputs_hash`, `acquired_at_ms`, and
`valid_until_ms`.

Payload JSON uses the existing Resolver V2 canonical encoding: sorted ASCII
snake-case keys, UTF-8, NFC strings, canonical decimal-string timestamps, no
floats, no defaults, and lowercase 32-byte hexadecimal hashes. Its signing
bytes are exactly:

```text
PROPHET_VERIFIER_ATTESTATION_V1\0
+ u32_le(len(canonical_payload))
+ canonical_payload
```

The frozen payload field named `job_id` is the **settlement authorization job
ID** (`settlement_authorization_job_id`): the SHA-256 digest of
`PROPHET_SETTLEMENT_JOB_V1\0` followed by
canonical JSON containing exactly `cluster_genesis_hash`, `program_id`,
`market`, `resolver_definition_hash`, `evidence_hash`, `proof_hash`, and
`public_inputs_hash`.

This is deliberately different from `coordinator_job_id`, the durable SQLite
workflow identifier computed under `PROPHET_RESOLUTION_COORDINATOR_JOB_V1\0`.
`coordinator_job_id` supports resumable work only; it is never a settlement
authorization proof and must not be substituted into an attestation. Future
signer services recompute `settlement_authorization_job_id` from the signed
attestation bindings.

The verifier's Ed25519 public key, ID, version, and implementation digest are
trusted runtime configuration. The private key is referenced only through its
environment-secret name and is never present in YAML. Future signer services
must verify both attestations against their own pinned identities rather than
trusting coordinator storage or request-provided descriptors.

The permanent deterministic compatibility vector is
[`verifier_attestation_v1.json`](/Users/dmitry/prophet/apps/oracle-attester/tests/fixtures/verifier_attestation_v1.json).
