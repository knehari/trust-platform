# Fuzzing

Requires nightly and `cargo-fuzz` (`cargo install cargo-fuzz --locked`).

```sh
mkdir -p fuzz/corpus/csr_parse && cp testdata/csr/*.der fuzz/corpus/csr_parse/
cargo +nightly fuzz run csr_parse fuzz/corpus/csr_parse -- -max_total_time=300
```

CI runs a short smoke campaign on every PR; long campaigns run on a schedule.
Every crash found becomes a regression test vector under `testdata/`.
