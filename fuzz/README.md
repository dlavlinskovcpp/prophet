# Prophet arithmetic fuzzing

Install the Rust fuzzing wrapper once with `cargo install cargo-fuzz`, then run:

```bash
cd fuzz
cargo fuzz run arithmetic -- -max_total_time=300
cargo fuzz run settlement -- -max_total_time=300
```

The targets use the program's host-only `fuzzing` feature and never expose an
additional on-chain instruction. Crashing inputs are retained by `cargo fuzz`
under `fuzz/artifacts/`; minimize and promote them to `fuzz/corpus/` before
fixing a defect.
