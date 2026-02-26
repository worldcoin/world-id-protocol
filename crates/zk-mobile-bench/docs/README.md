# zk-mobile-bench Docs

`zk-mobile-bench` contains mobile-facing benchmarks for World ID proof generation.

## Contents

- `benchmark-functions.md`: What each benchmark measures.
- `ci-browserstack.md`: How CI/PR-triggered BrowserStack runs are configured.

## Quick Start

Host sanity run (no mobile device):

```bash
cargo run -p zk-mobile-bench --example run_local --release
```

Direct mobench run (example):

```bash
cargo-mobench run \
  --target ios \
  --function zk_mobile_bench::bench_nullifier_proving_only \
  --iterations 30 \
  --warmup 5 \
  --config crates/zk-mobile-bench/bench-config.ios.toml \
  --release \
  --fetch \
  --summary-csv \
  --output target/mobench/ci/ios/nullifier-proving.json
```

Note: `warmup` is an iteration count (not milliseconds).

Config and matrix templates live in:

- `crates/zk-mobile-bench/bench-config.toml`
- `crates/zk-mobile-bench/bench-config.ios.toml`
- `crates/zk-mobile-bench/bench-config.android.toml`
- `crates/zk-mobile-bench/device-matrix.yaml`
- `crates/zk-mobile-bench/device-matrix.ios.low-spec.yaml`
- `crates/zk-mobile-bench/device-matrix.android.low-spec.yaml`
