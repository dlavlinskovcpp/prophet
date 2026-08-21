# RC4 Batch 4 — bounded-resource hardening

Baseline: `e0b012c4105575d851b6bb43f2db040cdf311e5f`.

This batch is limited to resolver-registry request/response bounds, proof-fetch
HTTP/decoded bounds, resolver-registry audit durability, bounded rate-limiter
state, X-Forwarded-For policy, and strict legacy zkTLS boolean parsing. It does
not change protocol/on-chain semantics, Resolver V2 serialization, NotaryConfig,
P-01..P-07, dependency versions, CI, or settlement architecture.

## Size controls

All limits below are bytes. Overflow fails closed; data is not truncated.

| Setting | Default | Limits | Overflow behavior |
| --- | ---: | --- | --- |
| `RESOLVER_REGISTRY_MAX_REQUEST_BYTES` | `100000` | Actual resolver-registry publish request body consumed by the application | HTTP 413 before JSON parsing |
| `RESOLVER_REGISTRY_MAX_RESPONSE_BYTES` | `256000` | Raw HTTP response returned to the resolver-registry client | Abort streamed read before JSON parsing |
| `PROOF_HTTP_MAX_RESPONSE_BYTES` | `4000000` | Raw HTTP proof-fetch response | Abort streamed read before JSON parsing |
| `PROOF_MAX_BYTES` | `2000000` | Decoded proof bytes | Reject before/full decode where encoded length proves overflow, then verify decoded length |
| `PUBLIC_INPUTS_MAX_BYTES` | `256000` | Decoded public-input bytes | Same fail-closed behavior as proof bytes |
| `RATE_LIMIT_MAX_IDENTITIES` | `10000` | Live in-memory rate-limit identities | New identities fail closed when capacity is full; active identities are not evicted |

All positive limits are runtime-validated. Reverse-proxy body limits are defense
in depth and are not a replacement for the application limits above.

## Resolver-registry request body

`Content-Length` is only an early-rejection hint. Missing `Content-Length` does
not imply zero bytes. The publish endpoint consumes the request stream into a
bounded buffer and stops immediately when the actual-byte limit would be
crossed. JSON parsing happens only after the bounded read succeeds. Malformed or
negative `Content-Length` fails closed; a declared length above the configured
limit is rejected before body consumption.

## Proof and resolver HTTP clients

The proof fetcher and resolver-registry client use streaming HTTP response
consumption. They count actual received bytes and stop reading on overflow
before JSON decoding. Proof/public-input base64 is strict (`validate=True`) and
is checked against the configured decoded-size limit both before allocation
when encoded length is sufficient to prove overflow and again after decoding.

No proof body, resolver body, bearer credential, or full attacker payload is
included in the new error text.

## Resolver audit durability

Production resolver-registry runtime validation requires the audit path to be
absolute and under `/app/audit`. Operated devnet, public-devnet, and mainnet-beta
compose mount a separate durable host path at `/app/audit`, independent from the
resolver store. Recreating the container therefore preserves the JSONL audit
file when `PROPHET_RUNTIME_ROOT` is preserved.

## Rate limiter and X-Forwarded-For

The sliding-window limiter periodically removes expired queues and has an
explicit maximum identity cardinality. If capacity is exhausted while all
tracked identities remain active, an unknown identity is denied rather than
evicting an active identity and weakening rate-limit semantics.

Bearer material is represented in limiter keys only by a bounded SHA-256
digest prefix; full tokens are not retained.

`RATE_LIMIT_TRUST_X_FORWARDED_FOR` defaults to false, including
production-shaped examples. Enable it only when the service is reachable
exclusively through a trusted reverse proxy that sanitizes/overwrites incoming
`X-Forwarded-For`. Direct service exposure must keep it disabled. When enabled,
the first forwarded address must parse as an IP address; malformed input falls
back to the direct peer identity.

## Legacy zkTLS status parsing

Legacy Reclaim response status accepts only actual JSON booleans. String,
numeric, null, missing, or conflicting `ok`/`valid` representations fail
closed. In particular, the string `"false"` is never accepted through Python
truthiness.

## Resource-bound review note

This scoped patch does **not** modify the production primary/independent bound
zkTLS HTTP verifier implementations because those files are outside the Batch 4
diff allowlist. A resource-bound review must still classify their outbound
response reads. If they remain unbounded, Batch 4 cannot receive a PASS verdict
without explicit scope authorization for those production verifier files.
