# Signed-oracle runtime keys

`TrustedOracleKeyRegistry` is immutable public runtime state. A record binds an
oracle identity, one or more resolver IDs, a base58 Solana public key, unique
key epoch, activation timestamp, optional retirement timestamp, allowed signed
message versions, and `active`/`retired` status. No private material is stored.

Lookup uses the signed source timestamp, never wall-clock time. Activation is
inclusive; retirement is exclusive. A historical message can validate after a
key is retired only when its source timestamp lay inside that key's interval.
Resolver and message-version scopes are mandatory and fail closed.

Overlapping active epochs are fail-closed: selection succeeds only when exactly
one record matches the source timestamp, resolver scope, and message version.
The registry never chooses a preferred key from an overlap. Registry lookup has
no influence on canonical signed-oracle message serialization.

The legacy adapter’s `key_id` and `key_set_version` are bound by separate
public runtime metadata to an oracle identity. `RegistryBackedOracleKeyring`
captures the trusted resolver and message-version context, resolves that
identity through the immutable registry, then returns the selected public key
through the legacy interface. This binding is runtime-only and never changes
canonical signed message bytes.

Records are sorted before the domain-separated
`PROPHET_SIGNED_ORACLE_RUNTIME_KEYS_V1\0` fingerprint is computed. Equivalent
input order therefore has the same fingerprint. A runtime configuration with
`signed-oracle` enabled must reference a parseable public registry; its
fingerprint becomes part of the runtime configuration fingerprint. Production
rejects registry paths marked `test` or `fixture`; test fixtures require test
mode explicitly.

## Canonical-message compatibility

The authoritative signed transport is the existing `signed_oracle_message`
frame. Its canonical bytes, and the deterministic SHA-256 message hash recorded
in evidence metadata, do not include `LegacyKeyBinding`, an oracle-identity
mapping, a runtime configuration fingerprint, or a registry fingerprint.
Those values are out-of-band runtime authorization metadata only.

The registry-backed runtime path and the intentional legacy `OracleKeyring`
path therefore consume identical signed bytes. Runtime authorization selects the
trusted public key; it does not alter the message bytes that key verifies.
