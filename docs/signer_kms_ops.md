# Signer / KMS Operations — Retired Generic Path

The historical generic KMS signer path is retired for production settlement. The primary signer operations runbook is now `docs/signer_vault_ops.md`, which documents the fixed-role boundary and the prohibition on same-process A+B credentials.

That document covers the current Vault Transit-first operated path, signer dry-runs, allowlist rotation, and compromised-key response.

The historical generic KMS backend remains only as isolated compatibility code and is not a production launch route.
