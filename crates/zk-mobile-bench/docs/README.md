# zk-mobile-bench

Mobile benchmarks for World ID ZK proof generation using [mobench](https://github.com/worldcoin/mobile-bench-rs).

## Quick Start

Install mobench:

```bash
cargo install mobench --git https://github.com/worldcoin/mobile-bench-rs --tag v0.1.28 --locked
```

Build and run locally:

```bash
cargo-mobench build --target ios --release --crate-path crates/zk-mobile-bench
cargo-mobench package-ipa --method adhoc --crate-path crates/zk-mobile-bench
cargo-mobench package-xcuitest --crate-path crates/zk-mobile-bench
```

Run a benchmark on BrowserStack:

```bash
cargo-mobench run \
  --target ios \
  --function zk_mobile_bench::bench_nullifier_proving_only \
  --iterations 30 \
  --warmup 5 \
  --devices "iPhone 11-13" \
  --crate-path crates/zk-mobile-bench \
  --release \
  --fetch
```

BrowserStack runs remain the right path for timing and memory benchmarks.
BrowserStack native profiling is unsupported in `mobench` `0.1.28`; use the
local provider for native capture.

Capture a local native profile:

```bash
cargo mobench profile run \
  --target ios \
  --provider local \
  --backend ios-instruments \
  --crate-path crates/zk-mobile-bench \
  --function zk_mobile_bench::bench_nullifier_proving_only
```

Render a local markdown summary with per-function device comparison plots:

```bash
cargo mobench report summarize \
  --summary target/mobench/ci/ios/summary.json \
  --plots auto
```

`summary.md` uses `cpu_median_ms` and `peak_memory_kb` for canonical resource fields.
CI summaries and PR comments can include inline `plots/*.svg` when plot rendering succeeds.
Benchmark reports also preserve optional semantic `phases` emitted by
`mobench_sdk::timing::profile_phase(...)`.

## CI Triggers

- **PR comment**: `/mobench platform=both iterations=30 warmup=5`
- **PR label**: Add the `bench` label (dispatches after compile gate passes)
- **Manual**: Actions > "Mobile Benchmarks" > Run workflow

## Benchmark Functions

| Function | What it measures |
|---|---|
| `bench_query_proof_generation` | Full π1 (witness + proving) |
| `bench_query_witness_generation_only` | π1 witness generation only |
| `bench_query_proving_only` | π1 Groth16 proving only |
| `bench_query_proof_only` | π1 proving with cached inputs |
| `bench_nullifier_proof_generation` | Full π2 (witness + proving) |
| `bench_nullifier_witness_generation_only` | π2 witness generation only |
| `bench_nullifier_proving_only` | π2 Groth16 proving only |
