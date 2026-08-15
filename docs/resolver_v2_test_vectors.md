# Resolver V2.0 Test Vectors

The permanent fixture is
[`resolver-v2/test-vectors/v2.json`](../resolver-v2/test-vectors/v2.json).
Rust, Python, and TypeScript consume it directly and must produce its six
recorded hashes without conversion.

It includes a normal zkTLS definition, NFC Unicode (`Café`), explicit null
optional fields, maximum `u64` timestamp, multiple evidence items, and an
`INVALID` outcome. Tests derive reordered-object, malformed encoding, numeric,
decomposed-Unicode, duplicate-evidence, stale-time, and binding-mismatch cases
from the fixture. Legacy compact-JSON SHA-256 must differ from every V2 hash.

New vectors require independent computation, canonical-byte review, and updates
to all three conformance suites. Do not regenerate fixtures during production.
