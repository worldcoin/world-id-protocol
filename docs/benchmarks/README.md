# Benchmark charts

Point-in-time charts produced from `crates/zk-mobile-bench` runs on the mobench device farm.
They are static snapshots; rerun the mobile benchmark workflow for current numbers.

## WIP-103 ownership proof (ProveKit v1, fixed four-thread Rayon pool)

- [`ownership-proof-mobile.svg`](./ownership-proof-mobile.svg): median witness-generation,
  proving, and combined runtimes per device (Android and iOS side by side).
- [`ownership-proof-generation-android-sina.svg`](./ownership-proof-generation-android-sina.svg):
  per-run distribution of combined proof generation on Android devices.
- [`ownership-proof-generation-ios-sina.svg`](./ownership-proof-generation-ios-sina.svg):
  per-run distribution of combined proof generation on iOS devices.

The benchmark functions behind these charts are `bench_ownership_witness_generation`,
`bench_ownership_proving`, and `bench_ownership_proof_generation`.
