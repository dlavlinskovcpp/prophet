# Resolver V2 coordinator HTTP service

Phase 6B2c exposes the existing durable `ResolutionCoordinator` as one
standalone FastAPI process. It is a transport boundary only: handlers validate
the existing canonical input, then call `coordinator.resolve()` once. They do
not call verifier clients directly, compare results, or mutate SQLite.

## Run locally

The service uses the existing strict runtime configuration plus the coordinator
section described in the [verifier client documentation](resolver_v2_verifier_client.md).
It requires an absolute persistent `coordinator.sqlite_path` for public-devnet,
separate A/B verifier descriptors and token references, a coordinator internal
token reference, and an outer sequential request timeout at least as large as
the sum of A and B client timeouts.

```sh
export PROPHET_COORDINATOR_RUNTIME_CONFIG=/secure/path/coordinator.yaml
export PROPHET_COORDINATOR_INTERNAL_TOKEN=replace-with-secret
export PROPHET_VERIFIER_A_TOKEN=replace-with-secret
export PROPHET_VERIFIER_B_TOKEN=replace-with-secret
make coordinator-run
```

`make coordinator-service-test` runs the transport integration tests. The host
and port are non-secret environment settings: `COORDINATOR_HOST` defaults to
`127.0.0.1` and `COORDINATOR_PORT` to `8400`.

## Endpoints

| Endpoint | Authentication | Behaviour |
| --- | --- | --- |
| `GET /health` | No | Process liveness only. Verifier outages do not affect it. |
| `GET /ready` | No | `200` only after config, SQLite schema, clients, and coordinator wiring construct successfully. |
| `POST /v1/resolve` | Bearer token | Resolve or resume one canonical durable job. |
| `GET /v1/resolutions/{job_id}` | Bearer token | Read existing durable state without verifier calls. |
| `GET /metrics` | No | Bounded-cardinality Prometheus text metrics. |

The public coordinator token is read only from the environment variable named
by `coordinator.internal_auth.token_env`; no secret values are stored in the
configuration or returned by endpoints. Bearer comparison is constant-time.

`POST /v1/resolve` accepts exactly the existing application request:

```json
{
  "market": "<32-byte lowercase hex>",
  "resolver_definition": { "...": "ResolverDefinitionV2" },
  "evidence": { "...": "EvidenceEnvelopeV2" },
  "trust_model": { "...": "TrustModelDescriptorV2" }
}
```

The outer `market` value is used only by the existing durable job identity. The
other fields are the same canonical inputs consumed by the coordinator and
verifier clients—no HTTP-specific protocol schema exists.

## Idempotency and resume

Canonical job identity is authoritative. HTTP does not create a second
idempotency store, and an optional request ID is correlation metadata only. A
repeat request with the same canonical content reuses its job:

- `AGREED` or `CONFLICT`: returns durable state and makes no verifier calls.
- partial A result: calls only missing B work on a later request.
- partial B result: symmetrically calls only missing A work.

If a verifier dependency fails, the endpoint returns `503`; no synthetic
result, conflict, or settlement action is created. Already committed durable
results remain in SQLite and a later identical request safely resumes missing
work.

## Limits, errors, and observability

The endpoint enforces `limits.request_max_bytes` before parsing and the
configured coordinator outer timeout around the existing orchestration call.
Malformed JSON is `400`, malformed canonical input is `422`, authentication
failure is `401`, unknown jobs are `404`, oversized requests are `413`, and
verifier dependency errors/timeouts are `503`. Safe persistence/internal errors
are `500`. A canonical invalid verifier result remains a real persisted result
and follows existing coordinator agreement semantics.

Bounded metrics include HTTP requests, resolve calls/failures, job states,
duration, inflight requests, and readiness. Safe structured logs contain a
bounded request ID, endpoint, durable state, safe failure category, and latency;
they never include credentials, proof material, or full evidence payloads.

## Out of scope

This service does not add Vault integration, threshold signing, Solana
settlement submission, Docker deployment, automatic retry workers, background
queues, schedulers, or new agreement/conflict logic.
