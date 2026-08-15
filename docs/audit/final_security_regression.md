# RC1 security regression evidence

Executed locally with the RC toolchain:

```sh
PROPHET_INVARIANT_SEQUENCE_COUNT=100000 cargo test -p prophet state_machine_preserves_economic_invariants_for_thousands_of_seeds --lib --locked
```

Result: **100,000 deterministic state-machine sequences passed**. The test
reports any failing seed in replayable hexadecimal form through
`PROPHET_INVARIANT_SEED`; no failures occurred, so no minimized reproduction
exists for this campaign.

The normal suite and source mapping are in
[`security_regression_matrix.md`](security_regression_matrix.md). Required RC
commands additionally include `cargo test --workspace --locked`, attester
tests (including Vault/signing, adapter, and multi-verifier cases), Python SDK
tests, TypeScript vectors, `bash scripts/check_zktls.sh`, `anchor build`, and
`make demo`. Coverage includes fee fragmentation, threshold validation,
INVALID conservation, order limits, fee/account authority, PDA substitution,
overflow/narrowing, double settlement/redemption, replay/freshness/domain
binding, verifier/signer conflicts and equivocation, Pyth/Chainlink failures,
zkTLS bindings, and signed-oracle replay/key rotation.

Critical pure arithmetic/property tests run in the Rust suite; no separate
long-running coverage-guided fuzzer corpus is currently shipped. That is a
known audit/release limitation, not a claim of formal verification.
