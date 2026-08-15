# Resolver V2 verifier HTTP client

Phase 6B2a provides a strict, outbound-only `VerifierServiceClient` for the
future coordinator. One client is created for exactly one configured verifier
slot (`A` or `B`) and can only `POST /v1/verify` to its fixed base URL. It does
not construct a verifier runtime, call local verification, contact the other
verifier, compare results, create coordinator jobs, or sign anything.

## Configuration

The optional `coordinator` section of the existing immutable runtime
configuration provides both explicit clients:

```yaml
coordinator:
  sqlite_path: "/var/lib/prophet/coordinator.sqlite"
  internal_auth:
    token_env: PROPHET_COORDINATOR_INTERNAL_TOKEN
  request_timeout_seconds: 20
  verifier_a:
    base_url: "https://verifier-a.internal.example"
    auth_token_env: PROPHET_VERIFIER_A_TOKEN
    expected_verifier_id: prophet.verifier.runtime.a
    expected_verifier_version: "2.0.0"
    expected_verifier_implementation_digest: "<64 lowercase hex characters>"
    request_timeout_seconds: 10
  verifier_b:
    base_url: "https://verifier-b.internal.example"
    auth_token_env: PROPHET_VERIFIER_B_TOKEN
    expected_verifier_id: prophet.verifier.runtime.b
    expected_verifier_version: "2.0.0"
    expected_verifier_implementation_digest: "<64 lowercase hex characters>"
    request_timeout_seconds: 10
```

All fields are required when `coordinator` is present. The coordinator timeout
must be at least the sum of its sequential A and B client timeouts. Unknown fields are
rejected. URLs must use `http` or `https`, include a host, and contain no
embedded credentials, fragment, query, or path beyond `/`. The client does not
follow redirects and disables implicit environment proxy configuration.

For public-devnet, `https` is preferred. Plain `http` is accepted only for an
explicitly controlled private service network (for example, a private
Docker/VPS subnet); operators must not expose that traffic to an untrusted
network. The client never silently downgrades an HTTPS URL.

`auth_token_env` is an environment-variable *name*, not a secret value. The
runtime configuration fingerprint includes the public URL and expected
identity, but never reads or includes token contents. Missing or empty token
values fail construction closed.

## Request and result boundary

`verify()` accepts the existing canonical runtime request fields:

```text
resolver_definition, evidence, trust_model
```

It validates those existing canonical objects, serializes them deterministically,
and sends them unchanged with an internal bearer token. It validates the returned
`VerificationResultV2` using the existing canonical parser and requires:

- exact expected adapter ID, version, and implementation digest;
- matching resolver definition hash; and
- matching evidence hash.

No market binding is invented because `VerificationResultV2` does not carry a
market field. Later orchestration binds the returned result to a durable
coordinator job.

## Failure policy

The client has typed, safe failures for configuration/authentication, timeout,
transport, remote-service status, malformed result, verifier-identity mismatch,
and request/result binding mismatch. It treats `401`/`403`, `400`/`413`/`422`,
`429`, redirects, and `5xx` as service failures—not canonical results. A timeout
or connection error is not retried and never becomes `VALID`, `INVALID`, or a
fallback call to A, B, or a local runtime.

Response bodies are streamed with the existing request-size limit as an upper
bound. Safe logs include only slot, expected verifier ID, bounded request ID,
status category, and latency; they exclude bearer tokens and request/evidence
contents.

## Deferred to Phase 6B2b

This phase intentionally does not perform A/B fan-out, agreement, SQLite state
mutation, retries, coordinator HTTP serving, Vault signing, or Solana
submission. Those operations remain outside this client boundary.
