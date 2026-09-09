# Mobile ZK baselines

Checked-in BrowserStack reference results for the seven `zk-mobile-bench` functions.

| File | Role |
| --- | --- |
| [`LATEST.md`](LATEST.md) | Human-readable current numbers |
| [`meta.json`](meta.json) | Provenance (commit, run, devices, mobench version) |
| [`ios/summary.json`](ios/summary.json) | Machine-readable iOS mobench summary (when present) |
| [`android/summary.json`](android/summary.json) | Machine-readable Android mobench summary (when present) |

## When these update

Baselines are rewritten only by a successful **Mobile Benchmarks** run on `main` with an empty `pr_number` (Actions → Mobile Benchmarks → Run workflow). Typical reason: circuit or proving-stack change that warrants a new reference.

PR `/mobench` and `bench`-label runs compare against these files when `meta.status` is `ready`; they do **not** modify them. Artifact-based baselines are not used.

## Compare locally

```bash
cargo-mobench ci check-run \
  --results-dir target/mobench/ci/ios \
  --baseline crates/zk-mobile-bench/baselines/ios/summary.json \
  --regression-threshold-pct 5.0
```
