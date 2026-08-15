# Frozen protocol surface for audit

The following interfaces are treated as audit-frozen. Any change requires a
new audit-impact assessment, compatibility report, fixture update, and release
approval. The authoritative migration snapshot is
[`anchor_0_30_protocol_snapshot.json`](../migration/anchor_0_30_protocol_snapshot.json).

## On-chain ABI

Frozen instructions are `initialize_market_v2`, `initialize_notary_config`,
`place_order`, `match_orders`, `cancel_order`, `lock_market`, `unlock_market`,
`sync_market_status`, `update_market_schedule`, `set_market_fee_config`,
`transfer_market_authority`, `update_notary_config`,
`resolve_market_threshold`, `emergency_resolve_invalid`, `redeem`,
`claim_refunds`, and `withdraw_protocol_fees`. Their Anchor discriminators,
argument layouts, account metas, error behavior, events, account
discriminators, and account allocation sizes are frozen by the snapshot and
the generated IDL under `target/idl/` after a pinned build.

Frozen account schemas are `Market`, `Order`, `Position`, and `NotaryConfig`;
including enum encodings, reserved bytes, field ordering, allocation, and
rent-exempt account sizing. Review sources in `programs/prophet/src/state/`.

Frozen PDA seeds are market `(b"market", resolver_hash, open_ts_le)`, notary
config `(b"notary_config", authority)`, order `(b"order", market, owner,
seq_le)`, and position `(b"position", market, owner)`. The authoritative
derivations are in `sdk/python/prophet_sdk/pdas.py` and the migration snapshot.

## Resolution and off-chain contracts

`PROPHET_RESOLVE_V2` is frozen byte-for-byte: domain, program ID, market,
notary config, resolver hash, timestamps, notary-config version, outcome,
proof hash, and public-input hash. See `programs/prophet/src/utils/attestation.rs`
and `docs/attestation_format.md`.

Resolver V2 canonical schemas, domain tags, canonical JSON rules, integer
rules, and component hash byte layouts are frozen in
`docs/resolver_v2_spec.md` and its Rust/Python/TypeScript vectors. Legacy
resolver hashing and legacy settlement frames remain separately frozen by
compatibility tests.

Frozen signer-facing contracts include signed-oracle frames,
`PROPHET_RESOLVE_V2`, signer policy fields, threshold/notary-config version
binding, Vault Transit request constraints, and replay/equivocation domains.
See `docs/resolver_v2_signed_oracle_adapter.md`, `docs/signer_vault_ops.md`,
and `docs/resolver_v2_multi_verifier.md`.

## SDK surface

The public Python SDK exports in `prophet_sdk.__all__`, client instruction
methods, PDA derivations, resolver hash helpers, Resolver V2 hashing, and the
agent facade (`ProphetAgent`, `ResolverConfig`, `MarketHandle`) are frozen
semantically. SDK ergonomics may add wrappers only when they do not alter
instruction bytes, PDA derivation, validation, or settlement construction.
