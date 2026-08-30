# Fixed-role signer and Vault operations

RC4.4 P0C4 retires the generic remote signer and any same-process A+B signing
workflow. Production settlement uses two separately deployed fixed-role
processes:

- signer A has only the A Vault policy/key, A RPC trust, A admission replay
  journal, and A P0C2 journal;
- signer B has the corresponding B-only resources;
- the coordinator and submitter receive public identities and raw signatures,
  never Vault tokens or signer private material.

The old `REMOTE_SIGNER_*`, `NOTARY_SIGNER_MODE=remote`, shared Vault-token, and
dual-key key-map settings are retired and must not be placed in a production
environment file. `src/remote_signer_main.py` is a fail-closed compatibility
stub and is not a launch target.

Role-local recovery may be performed one role at a time under that role's
Vault policy. The operator must not load A and B credentials into the same
process, shell session, or recovery invocation. Public-devnet remains paused
and mainnet remains blocked.
