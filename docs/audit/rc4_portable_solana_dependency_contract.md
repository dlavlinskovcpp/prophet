# RC4 Portable Python Solana Dependency Contract

RC4 Batch 2B addresses the cross-platform dependency defect discovered while
validating the production container build. RC3 and RC4 Batch 2 originally used
`solana==0.32.0` with `solders==0.20.0`. The Linux ARM64 production import
path exposed that the Solders 0.20.0 ARM64 wheel did not provide the RPC response
modules required by `solana.rpc.api`.

Upstream Solders 0.21.0 restored RPC modules on Linux AArch64, and solana-py
0.33.0 pairs with Solders 0.21.0 for the AArch64 compatibility fix. RC4 therefore
uses the exact portable runtime pair:

- `solana==0.33.0`
- `solders==0.21.0`

Verified in this Batch 2B execution with Python 3.11 and the same committed
Poetry lock contracts:

- Linux ARM64 (`linux/arm64`, runtime machine `aarch64`)
- Linux AMD64 (`linux/amd64`, runtime machine `x86_64`)
- macOS host machine `arm64` (`macOS-26.5.1-arm64-arm-64bit`)

For all verified platforms, `solders.rpc.responses`, `solana.rpc.api`, and
Prophet package imports succeeded with the exact pair above. Runtime-only
installs excluded pytest and pytest-asyncio.

The permanent Resolver V2 vectors and protocol source were not modified.
Three oracle regression tests that explicitly asserted the former
`solders==0.20.0` runtime contract were updated only in their test labels and
exact metadata guard to assert `solders==0.21.0`; their serialization,
round-trip, signature, type, and byte assertions were left unchanged.
Resolver V2 golden tests, the Prophet and resolver-v2 Rust library suites, the
Solders-sensitive settlement/signing matrix, full SDK tests, full matching
keeper tests, and the full oracle-attester non-E2E suite passed without
regenerating expected protocol bytes.

This dependency portability correction does not change `PROPHET_RESOLVE_V2`,
Resolver V2 hashes, NotaryConfig architecture, or P-01 through P-07 behavior.
