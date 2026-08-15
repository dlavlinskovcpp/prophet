# Vault Transit single-signer compatibility

Phase 6C2 signs one already-canonical Prophet settlement message with one
already-pinned Vault Transit signer. The authoritative serializer is
`build_legacy_settlement_message()` in
`apps/oracle-attester/src/resolver_v2_pipeline.py`; it is the established
byte-for-byte `PROPHET_RESOLVE_V2` layout and matches the on-chain
`resolution_message_v2` implementation.

The Vault signer receives those bytes directly. It does not reconstruct
resolution fields, hash/prehash the message, append runtime metadata, add a
coordinator job ID, or modify domain separation. The existing Vault Transit
request sends the raw byte payload as base64 `input` with an explicit
`key_version`. Transit’s versioned signature response is required to identify
the configured key version.

Before a signature is returned, the client validates its pinned Transit
metadata, requires the exact configured version, parses the strict 64-byte
signature, and verifies it locally against the configured public key and exact
message bytes. A Transit success response alone is not sufficient.

The immutable result contains only signer ID, public key, key version, signature
bytes, and message digest. Tokens and private key material never leave Vault.
There is no local-keypair, filesystem-keypair, bootstrap-key, alternate Vault
key, or local verifier fallback.

The permanent test vector freezes a literal `PROPHET_RESOLVE_V2` byte sequence
with zero program/market/config keys, resolver hash `04…04`, timestamps `-7`
and `42`, config version `9`, `INVALID` outcome, proof hash `05…05`, and public
inputs hash `06…06`. Tests prove the serializer emits exactly those bytes,
Vault-generated signatures verify through the existing Ed25519 instruction
layout, and any single canonical field mutation invalidates the unchanged
signature.

The deterministic Transit signer exists only in localtest/test mode and is
never accepted as public-devnet production configuration. It contains test-only
private material solely for compatibility tests.

Phase 6C2 does not orchestrate A+B signatures, enforce a 2/2 policy, call the
coordinator, construct or submit Solana transactions, or automatically sign an
`AGREED` job.
