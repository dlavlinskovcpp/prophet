# Attestation Format

This document defines the signed message formats used by Prophet market resolution.

## Why This Exists

Resolution is permissionless, but signatures are constrained to canonical message bytes.  
The program validates both:

- the signer identity (oracle or allowed notary key)
- exact message bytes (domain + fields + hashes)

## V1 Message (Single Oracle, Compatibility Only)

Domain: `PROPHET_RESOLVE_V1`

Byte layout:

1. domain bytes (`PROPHET_RESOLVE_V1`)
2. `market` pubkey bytes (32)
3. `resolver_hash` (32)
4. `open_ts` little-endian i64 (8)
5. `outcome` u8 (`1=Yes`, `2=No`, `3=Invalid`)
6. `proof_hash` (32)
7. `public_inputs_hash` (32)

Used by:

- on-chain instruction: `resolve_market_signed`
- SDK: `ProphetClient.resolve_market_signed(...)`
- attester legacy flow only when `ALLOW_LEGACY_SINGLE_ORACLE=1`

## V2 Message (Threshold Notaries)

Domain: `PROPHET_RESOLVE_V2`

Byte layout:

1. domain bytes (`PROPHET_RESOLVE_V2`)
2. `program_id` pubkey bytes (32)
3. `market` pubkey bytes (32)
4. `notary_config` pubkey bytes (32)
5. `resolver_hash` (32)
6. `open_ts` little-endian i64 (8)
7. `resolve_ts` little-endian i64 (8)
8. `notary_config_version` little-endian u64 (8)
9. `outcome` u8 (`1=Yes`, `2=No`, `3=Invalid`)
10. `proof_hash` (32)
11. `public_inputs_hash` (32)

Used by:

- on-chain instruction: `resolve_market_threshold`
- SDK: `ProphetClient.resolve_market_threshold(...)`
- attester threshold flow by default

## Hash Inputs

- `proof_hash = sha256(proof_bytes)`
- `public_inputs_hash = sha256(public_inputs_bytes)`

The hashes are stored on-chain when the market is resolved.

## Notes

- On-chain verification does not re-run zkTLS proof cryptography.
- zkTLS verification happens in the attester service.
- Signatures are passed through Solana's Ed25519 verify instruction and checked against canonical message bytes in the program.
- New deployments should prefer V2 threshold messages and v2 markets.
