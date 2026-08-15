# Mainnet blockers

Mainnet is blocked until all of the following have dated evidence:

- Independent external security audit completed; all critical findings fixed.
- All high findings fixed, or explicitly accepted with strong written justification.
- Public devnet full lifecycle and conflict acceptance tests verified.
- Live monitoring and alert delivery verified.
- Dedicated signer, Vault, deployment-authority, and compromised-signer-removal drills exercised.
- Backup/restore and rollback drills exercised with retained evidence.
- RC soak period completed under defined traffic and failure criteria.
- Final security regression and reproducible artifact verification green.

Additional blockers: no formally verified core, off-chain resolver/oracle and
RPC dependencies remain, and no current evidence proves independent external
review of multi-verifier, signer, or upgrade authority assumptions.
