# Security regression seeds

`cargo test -p prophet --lib state_machine_preserves_economic_invariants_for_thousands_of_seeds`
executes 4,096 deterministic lifecycle sequences. It reports any failing seed
as hexadecimal and it can be replayed exactly with:

```bash
PROPHET_INVARIANT_SEED=0x0123456789abcdef \
  cargo test -p prophet --lib security_tests::state_machine_preserves_economic_invariants_for_thousands_of_seeds -- --exact
```

Promote every discovered seed to the table below, including its vulnerability
class and the regression-test name. No failures were known when this Phase 2
test corpus was added.

| Seed | Class | Regression test |
| --- | --- | --- |
| `0x8f6a6c297d314be5` | Baseline deterministic state-machine corpus | `state_machine_preserves_economic_invariants_for_thousands_of_seeds` |
