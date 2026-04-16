# Signer / KMS Operations

The primary signer operations runbook moved to `docs/signer_vault_ops.md`.

That document covers the current Vault Transit-first operated path, signer dry-runs, allowlist rotation, and compromised-key response.

`REMOTE_SIGNER_BACKEND=aws_kms` still exists for compatibility, but it is no longer the default operated workflow.
