# Prophet Protocol (Claim MVP)

Prophet is a Solana/Anchor bonded-claims protocol.

## Core On-Chain Components

Program: `programs/prophet`

Main claim-path accounts:

- `Claim`: claim config, recipients, resolver hash, proof/public-input hashes, resolve/redeem status
- `NotaryConfig`: threshold notary set for t-of-n resolution

Main claim-path instructions:

- Claim lifecycle: `create_claim`, `resolve_claim_signed`, `resolve_claim_threshold`, `redeem_claim`
- Notary admin: `initialize_notary_config`, `update_notary_config`

Claim PDA seed model:

- `claim` PDA: `[b"claim", issuer, claim_id_le]`
- `claim` vault: ATA with authority = `claim` PDA

## Off-Chain Components

Service: `apps/oracle-attester`

Responsibilities:

- load claim state and resolver definition
- evaluate resolver predicate against public inputs
- optionally verify zkTLS provider evidence
- build canonical claim resolve message/signatures
- submit permissionless resolve transaction

## Trust / Verification Model

- zkTLS verification is off-chain in attester.
- on-chain verifies Ed25519 signatures and exact canonical message bytes.
- on-chain stores `proof_hash` and `public_inputs_hash` for auditability.
- threshold mode reduces signer trust by requiring distinct t-of-n notary signatures.

## SDK Integration

SDK: `sdk/python/prophet_sdk`

Primary claim-path methods:

- `create_claim(...)`
- `resolve_claim_signed(...)`
- `resolve_claim_threshold(...)`
- `redeem_claim(...)`

## Legacy Paths

Market/CLOB instructions and SDK methods remain in the repository for backward compatibility, but claim-path development is the default focus.
