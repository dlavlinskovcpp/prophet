# Attestation Format

This document defines canonical signed message formats used by Prophet resolution.

## Claim V1 (Single Oracle)

Domain: `PROPHET_CLAIM_RESOLVE_V1`

Byte layout:

1. domain bytes (`PROPHET_CLAIM_RESOLVE_V1`)
2. `program_id` pubkey bytes (32)
3. `claim` pubkey bytes (32)
4. `resolver_hash` (32)
5. `issuer` pubkey bytes (32)
6. `claim_id` little-endian u64 (8)
7. `resolve_ts` little-endian i64 (8)
8. `outcome` u8 (`1=Pass`, `2=Fail`, `3=Invalid`)
9. `proof_hash` (32)
10. `public_inputs_hash` (32)

Used by:

- on-chain instruction: `resolve_claim_signed`
- SDK: `ProphetClient.resolve_claim_signed(...)`
- attester claim single-oracle flow

## Claim V2 (Threshold Notaries)

Domain: `PROPHET_CLAIM_RESOLVE_V2`

Byte layout:

1. domain bytes (`PROPHET_CLAIM_RESOLVE_V2`)
2. `program_id` pubkey bytes (32)
3. `claim` pubkey bytes (32)
4. `notary_config` pubkey bytes (32)
5. `resolver_hash` (32)
6. `issuer` pubkey bytes (32)
7. `claim_id` little-endian u64 (8)
8. `resolve_ts` little-endian i64 (8)
9. `outcome` u8 (`1=Pass`, `2=Fail`, `3=Invalid`)
10. `proof_hash` (32)
11. `public_inputs_hash` (32)

Used by:

- on-chain instruction: `resolve_claim_threshold`
- SDK: `ProphetClient.resolve_claim_threshold(...)`
- attester claim threshold flow

## Hash Inputs

- `proof_hash = sha256(proof_bytes)`
- `public_inputs_hash = sha256(public_inputs_bytes)`

These hashes are stored on-chain when a claim is resolved.

## Legacy Market Formats

Legacy market formats (`PROPHET_RESOLVE_V1` and `PROPHET_RESOLVE_V2`) are still supported for backward compatibility but are not the default product path.

## Fixed Vectors

Shared fixture source:

- `tests/fixtures/claim_message_vectors.json`

Exact byte-vector tests live in:

- `sdk/python/tests/test_claim_message_vectors.py`
- `apps/oracle-attester/tests/test_claim_message_vectors.py`
- `tests/claim_message_vectors.ts`
