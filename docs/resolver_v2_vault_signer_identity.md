# Vault Transit signer identity

Phase 6C1 establishes public identity and metadata validation for two future
Resolver V2 signer roles. The authoritative Vault integration remains
`apps/oracle-attester/src/vault_transit.py`; the Phase 6C1
`VaultTransitSignerClient` wraps its metadata-read path only and deliberately
has no signing method.

## Configuration and separation

The optional strict runtime configuration section is:

```yaml
signing:
  vault:
    address: "https://vault.internal.example"
    auth: {token_env: PROPHET_VAULT_TOKEN}
    transit_mount: transit
    request_timeout_seconds: 10
    backend: vault-transit
  signers:
    a:
      signer_id: resolver-signer-a
      key_name: prophet-devnet-resolution-a
      expected_public_key: "<canonical Solana Ed25519 public key>"
      expected_key_version: 1
    b:
      signer_id: resolver-signer-b
      key_name: prophet-devnet-resolution-b
      expected_public_key: "<canonical Solana Ed25519 public key>"
      expected_key_version: 1
```

All fields are explicit and unknown fields are rejected. Signer A and B must
have different IDs, Transit key names, and pinned public keys. Public keys use
the existing canonical Solana/base58 `Pubkey` representation; alternate or
malformed encodings are rejected. In public-devnet a real Vault Transit address
must use HTTPS.

`token_env` contains only the environment-variable name. The token value is
read at construction, never placed in configuration fingerprints, logs, errors,
or runtime identities. Missing and empty values fail closed. Production never
accepts YAML/private-key material, seed phrases, filesystem keypairs, or a
bootstrap-key fallback.

## Identity validation

For each signer, the client reads the fixed Transit key metadata path from
trusted configuration. It requires an `ed25519` key, rejects detectable
disabled/deleted/non-signing keys, requires the exact configured version in the
metadata `keys` map, parses that version’s public key, and compares it exactly
against the configured pin. No newer/latest key version is selected implicitly.

On success it returns an immutable public `VaultTransitSignerIdentity` with
signer ID, key name/version, public key, key type, and non-secret config/public
key fingerprints. It contains no token or private material.

Vault unreachable/authentication/permission/key-not-found, malformed metadata,
wrong type, missing version, and public-key mismatch have distinct fail-closed
typed failures. The configuration fingerprint binds the Vault address, mount,
and both signer identity/key/version/public-key records, but not the token.

## Production/test boundary

`backend: deterministic-test` exists only for explicit localtest + test-mode
unit infrastructure and requires an injected test transport. It is rejected for
public-devnet and production configurations. It has no signing API. The
public-devnet template intentionally contains unresolved placeholders, which
must fail validation/readiness until real managed keys are provisioned.

## Out of scope

Phase 6C1 does not sign Prophet resolution messages, enforce a 2/2 threshold,
call the coordinator, rotate keys, construct Solana transactions, or submit
settlement. Those remain later phases.
