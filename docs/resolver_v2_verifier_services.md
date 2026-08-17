# Resolver V2 verifier services

Phase 6A1 exposes two transport-only FastAPI applications. Each application
constructs one immutable verifier runtime at process startup and delegates every
accepted request exactly once to that runtime:

```text
Verifier A HTTP -> ResolverVerifierRuntime(A).verify()
Verifier B HTTP -> ResolverVerifierRuntime(B).verify()
```

The services do not select adapters, inspect oracle keys, verify proofs or
signatures, compare verifier outputs, or submit settlement transactions. Those
actions remain in the existing runtime and later pipeline phases.

## Startup and execution

Both services require a strict runtime configuration file and an internal token
provided by the environment. The configuration's `verifier.implementation_id`
and `verifier.version` must exactly match the service being started; a mismatch
leaves the process live but not ready.

```sh
export PROPHET_VERIFIER_RUNTIME_CONFIG=/secure/path/verifier-a.yaml
export PROPHET_VERIFIER_INTERNAL_TOKEN=replace-with-secret
make verifier-a-run

export PROPHET_VERIFIER_RUNTIME_CONFIG=/secure/path/verifier-b.yaml
make verifier-b-run
```

`make verifier-services-test` runs the HTTP integration coverage. Host and port
are non-secret environment settings: `VERIFIER_HOST` defaults to `127.0.0.1`,
and the service ports default to `8301` (A) and `8302` (B).

Each process needs its own configuration with its expected identity:

| Process | Required `verifier.implementation_id` |
| --- | --- |
| A | `prophet.verifier.runtime.a` |
| B | `prophet.verifier.runtime.b` |

Verifier B keeps the existing independent deterministic backend for tests and
adds a production-only `independent-bound-http` proof checker. Verifier A uses
the primary `bound-http` proof checker through the normal runtime adapter
factory. The two production implementations have separate HTTP/parsing code,
and deployment preflight requires different service identities, auth references,
and proof-backend URLs. Neither implementation has a fallback to the other.

## Endpoints

| Endpoint | Behaviour |
| --- | --- |
| `GET /health` | Process liveness only; it remains successful during a transient backend outage. |
| `GET /ready` | `200` only after strict configuration and all required runtime dependencies construct successfully; otherwise `503`. |
| `GET /metrics` | Unauthenticated Prometheus text metrics. |
| `POST /v1/verify` | Authenticated canonical `runtime.verify()` request. |

There are no documentation, coordinator, administration, or settlement routes.

`POST /v1/verify` accepts exactly the existing runtime request object:

```json
{
  "resolver_definition": { "...": "canonical ResolverDefinitionV2" },
  "evidence": { "...": "canonical EvidenceEnvelopeV2" },
  "trust_model": { "...": "canonical TrustModelDescriptorV2" }
}
```

The endpoint requires `Authorization: Bearer <token>`, where the actual token
is read only from the environment variable named by `internal_auth.token_env`.
The configuration stores the variable name, never the token. Comparison uses a
constant-time comparison. A bounded, sanitized `X-Request-ID` is echoed on a
successful runtime evaluation and used only for observability.

The service rejects malformed input with `400`, missing or invalid credentials
with `401`, requests above `limits.request_max_bytes` with `413`, and canonical
request validation rejection with `422`. Runtime timeouts and unavailable
runtime failures return safe `503` responses. A canonical `REJECTED` or
`INVALID` verification result is still a successful HTTP evaluation (`200`) and
is returned unchanged as the VerificationResultV2-compatible payload.

The transport enforces `limits.request_timeout_seconds` and never returns a
later successful result for a timed-out request.

## Observability

The services emit JSON logs containing only verifier identity/version, the
non-secret runtime configuration fingerprint, request ID, bounded adapter
family, safe result category, and latency. They do not log credentials, secret
values, signed evidence bodies, or zkTLS proof bytes.

`/metrics` publishes bounded-cardinality metrics:

- `verifier_http_requests_total`
- `verifier_verification_total`
- `verifier_verification_failures_total`
- `verifier_request_duration_seconds`
- `verifier_inflight_requests`
- `verifier_readiness`

Labels are limited to service identity, endpoint, status/result category, and
known adapter family. Resolver IDs, markets, key IDs, request IDs, and raw
errors are never labels.

## Independence and scope

HTTP requests to A use only runtime A and requests to B use only runtime B.
The shared transport has no verification algorithm and does not route an A
request through B (or vice versa). Existing dual-verifier runtime tests and the
HTTP integration test enforce this boundary.

This phase deliberately does not add a coordinator/quorum engine, persistence
or conflict state, Vault signing, transaction submission, Docker orchestration,
or a monitoring-stack deployment.
