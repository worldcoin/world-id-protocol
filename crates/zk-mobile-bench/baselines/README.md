# Mobile ZK baselines

Checked-in BrowserStack reference results for the seven `zk-mobile-bench` functions.

| File | Role |
| --- | --- |
| [`LATEST.md`](LATEST.md) | Human-readable current numbers |
| [`meta.json`](meta.json) | Provenance (commit, run, devices, mobench version) |
| [`ios/summary.json`](ios/summary.json) | Machine-readable iOS mobench summary (when present) |
| [`android/summary.json`](android/summary.json) | Machine-readable Android mobench summary (when present) |

## When these update

Run **Actions → Mobile Benchmarks** on `main` with **`open_baselines_pr=true`** (leave `pr_number` empty). On success the workflow opens a PR that refreshes these files; merge that PR to adopt the new reference.

PR `/mobench` and `bench`-label runs post their own results in a sticky comment; they do **not** modify these files.
