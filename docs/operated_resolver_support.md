# Operated Resolver Support

Permissionless market creation and operated settlement support are separate
claims. Every operated market-creation route performs a fail-closed preflight:

1. the resolver definition exists;
2. it parses as the current canonical Resolver V2 definition;
3. its canonical V2 hash equals the requested on-chain `resolver_hash`;
4. its resolver type and complete adapter identity are enabled by the deployed
   runtime; and
5. the configured verifier implementation for that type is available.

The public classification is one of:

- `OPERATED_SUPPORTED`: all checks passed;
- `EXTERNAL_UNVERIFIED`: a non-zero resolver is present but no operated
  definition was supplied; or
- `UNSUPPORTED`: the definition, hash, adapter, deployment policy, or verifier
  check failed.

The matching keeper selects only hashes explicitly classified as
`OPERATED_SUPPORTED` in production environments. Unknown permissionless
markets remain outside its operated scope. A resolver may still be valid for a
permissionless market without being an operated-supported resolver.
