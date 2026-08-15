# Security regression matrix

| Finding / class | Regression coverage | Mitigation | Residual risk |
|---|---|---|---|
| Fragmented-fill fee evasion | `programs/prophet/src/security_tests.rs` (`property_fee_is_independent_of_fragmentation`) | Cumulative taker-cost fee delta | Arithmetic implementation defect |
| Bad notary threshold config | `validation/notaries.rs`, `security_tests.rs` | Threshold/key validation and version binding | Trusted config authority |
| INVALID rounding dust | `security_tests.rs` (`regression_invalid_rounding_carry_*`) | Deterministic carry accounting | Payout code defect |
| Order-slot exhaustion | `validation/market.rs`, state-machine tests | Per-user/global caps and close accounting | Economic spam within configured limits |
| Invalid fee recipient | `validation/token_accounts.rs`, fee tests | Owner/mint/vault checks | Authority misconfiguration before freeze |
| Invalid authorities | instruction account tests and market validation | Signer/authority constraints | Authorized-key compromise |
| PDA substitution | PDA/account constraint tests; SDK derivation tests | Canonical seeds and account ownership checks | Program/SDK defect |
| Narrowing/overflow | arithmetic tests and `property_overflow_boundaries_*` | Checked u128/u64 conversion | Untested arithmetic path |
| Verifier conflict | `test_resolver_v2_multi_verifier.py`, `test_resolver_v2_oracle_adapters.py` | 2/2 policy and persistent conflict state | Source/verifier outage |
| Signer equivocation | `test_resolver_v2_pipeline.py`, multi-verifier tests | Durable equivocation monitor before signing | Existing signature cannot be revoked |
| Stale/replayed oracle evidence | adapter and pipeline tests | Definition/market/cluster/replay/freshness binding | Operational clock/RPC assumptions |
