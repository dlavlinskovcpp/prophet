# Resolver V2 runtime configuration

`apps/oracle-attester/src/runtime_config.py` loads the version-1 YAML runtime
configuration used by future verifier processes. Parsing is strict: every
object has an exact field set, security-sensitive values have no defaults, and
the returned dataclasses are frozen.

Required fields are `environment`, `mode`, Solana cluster/genesis/program
binding, Resolver V2 version, verifier identity/version, unique approved
adapters, positive limits/freshness values, and an `internal_auth.token_env`
reference. The reference is an environment-variable *name*, never a token.

`public-devnet` requires `solana.cluster: devnet` plus nonempty genesis and
program bindings. Mainnet is rejected unless a future caller explicitly opts
in; there is no fallback. Production/test mode is explicit so later provider
factories can reject test-only dependencies in production.

The fingerprint is SHA-256 over domain tag
`PROPHET_RESOLVER_RUNTIME_CONFIG_V1\0` and canonical JSON of public
security-relevant fields. It excludes the token environment variable and all
secret contents, and is invariant to YAML field order.

Safe templates are in `deploy/operated/public-devnet/` and
`deploy/operated/localtest/`. Replace public bindings through the operator
configuration path; do not place credentials in either file.
