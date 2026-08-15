# Key management and compromise response

| Key class | Storage and use | Rotation / compromise response |
|---|---|---|
| Deployment/upgrade authority | Offline or hardware-controlled dedicated release identity | Stop releases, transfer/revoke authority per approved plan, redeploy only reviewed artifact |
| Market authority | Dedicated operational multisig/key, distinct from deployer | Transfer authority; review lifecycle actions and emergency INVALID use |
| Resolver governance/operator | Registry service identity in secret manager | Disable writes, preserve append-only evidence, deprecate/replace definitions |
| Threshold signer | One identity per signer; Vault Transit/HSM preferred | Update `NotaryConfig` version, remove key, recollect signatures; retain audit trail |
| Vault Transit key/token | Vault-managed transit key; short-lived authenticated access | Revoke Vault token, rotate transit key and key map, update signer policy |
| CI/test/demo keys | Ephemeral CI secrets or deterministic test-only fixtures | Never promote; revoke if exposed; fixtures are not production identities |

Production and test keys must never be generated, committed, placed in
`stack.env`, copied into audit bundles, or printed by demos. Secret references
belong in the deployment secret manager; repositories carry only examples and
public allowlists. Rotation must be rehearsed in testnet and must update
notary/config versions because the legacy settlement message binds that
version. See `docs/signer_vault_ops.md` and `docs/signer_kms_ops.md`.
