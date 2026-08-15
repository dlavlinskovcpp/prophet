# Prophet v1.0.0-rc1 release candidate

Baseline commit: `f9041e327ba384ce0c09fd6ed83263642cd5ae4d`.

| Item | Recorded value |
|---|---|
| Anchor | `anchor-cli 1.0.1` |
| Agave/Solana CLI | `3.1.10` |
| Rust | `1.89.0 (29483883e 2025-08-04)` |
| Node | `v20.19.6` |
| Program ID configuration | `913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A` |
| Cargo.lock SHA-256 | `06b6e2992dea8c86c37df179b218bde153276f9bc91790c3a8902b03b6abc0be` |
| yarn.lock SHA-256 | `bb7ad3c9953cf1f5b50e4b389a6e105f7e77419200d86247bba89e638bf419fa` |
| attester poetry.lock SHA-256 | `f129d7c3c164508397f743b73c134971a516c87e7494661d6e6990923fd119b5` |
| SDK poetry.lock SHA-256 | `e77e34530829e0c626752ff591e6cc4468914419074b35c1f6444f8f1f7e5ed6` |
| IDL SHA-256 | `9b81e7572be1044b83a72a75ce79cedd497302c23770ae44ec3e0bef12d6edad` |
| Reproducible local SBF binary SHA-256 | `6b0856068a82f998edd8e4276ae1fcbe54043362ce7b8a6a4aea80e115325053` |

The binary digest is a local pinned-toolchain artifact, not an independently
reproducible-build attestation. Regenerate and compare it from a clean,
hermetic release environment before deployment. See
[`v1_rc1_abi_snapshot.json`](v1_rc1_abi_snapshot.json).
