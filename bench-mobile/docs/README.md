# bench-mobile Docs

`bench-mobile` contains mobile-facing benchmarks for World ID proof generation.

## Contents

- `benchmark-functions.md`: What each benchmark measures.
- `ci-browserstack.md`: How CI/PR-triggered BrowserStack runs are configured.

## Quick Start

Host sanity run (no mobile device):

```bash
cargo run -p bench-mobile --example run_local --release
```

Direct mobench run (example):

```bash
cargo mobench run \
  --target ios \
  --function bench_mobile::bench_nullifier_proving_only \
  --iterations 30 \
  --warmup 5 \
  --config bench-config.ios.toml \
  --release \
  --fetch \
  --summary-csv \
  --output target/mobench/ci/ios/nullifier-proving.json
```

Note: `warmup` is an iteration count (not milliseconds).
