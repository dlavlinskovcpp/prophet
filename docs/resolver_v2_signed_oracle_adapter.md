# Resolver V2 Signed-Oracle Adapter

The signed-oracle adapter accepts only configured publisher keys and produces
canonical V2 evidence and verification results. It cannot sign or submit a
settlement transaction.

## Signed message

The exact signed bytes are:

```text
"PROPHET_SIGNED_ORACLE_V2\0" ||
u16_le(schema_length) || "prophet.signed-oracle-observation.v2" ||
u16_le(version_length) || "2.0.0" ||
u32_le(canonical_payload_length) || canonical_payload
```

The canonical payload has exactly `schema`, `schema_version`, `resolver_id`,
`market`, `outcome`, `source_timestamp_ms`, `sequence`,
`cluster_genesis_hash`, and `replay_domain`. It is canonical Resolver V2 JSON:
NFC strings, sorted ASCII-snake-case keys, compact UTF-8 JSON, decimal-string
integers, and no JSON numeric values or implicit defaults.

The definition binds message domain/schema, market, cluster, replay domain,
key-set version, maximum age, monotonic-sequence policy, and an explicit
`outcome_mapping`. Runtime key discovery is forbidden.

## Replay and rotation

Replay identity is `(resolver, market, cluster, replay_domain, key_id)`. A
monotonic policy rejects duplicate or lower sequence numbers. The signed frame
also prevents cross-market, cross-resolver, cross-cluster, and cross-version
replay.

`OracleKeyring` uses explicit immutable key epochs: key ID, public key, key-set
version, activation time, and optional retirement time. The key ID is carried
in evidence, so intentional overlap remains auditable. At the retirement
boundary the old key is invalid; unknown keys and versions never fall back.

## Failure modes and tests

Verification rejects malformed frames, invalid signatures, unknown/inactive
keys, wrong market/resolver/cluster/replay domain, wrong schema, stale or
future observations, unapproved outcomes, wrong trust/adapter/definition, and
duplicate sequence numbers. Tests cover these cases, key-rotation boundaries,
and conflicting signed outcomes using one sequence. No private keys, tokens, or
authenticated session material appear in audit output.
