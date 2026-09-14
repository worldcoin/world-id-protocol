# Mobile ZK results

Checked-in BrowserStack results for the seven `zk-mobile-bench` functions.

| File | Role |
| --- | --- |
| [`LATEST.md`](LATEST.md) | Human-readable current numbers |
| [`meta.json`](meta.json) | Provenance (commit, run, devices, mobench version) |
| [`ios/summary.json`](ios/summary.json) | Machine-readable iOS mobench summary (when present) |
| [`android/summary.json`](android/summary.json) | Machine-readable Android mobench summary (when present) |
| `ios/plots/`, `android/plots/` | Per-function SVG plots embedded by `LATEST.md` (when present) |

## When these update

Run **Actions → Mobile Benchmarks** on `main` with **`open_results_pr=true`**, **`device_profile=all`** (leave `pr_number` empty). The `all` profile runs the low/mid/high tiers from [`../device-matrix.yaml`](../device-matrix.yaml) so the snapshot and its plots cover the full device spread. On success the workflow opens a PR that refreshes these files; merge that PR to adopt the new snapshot.

PR `/mobench` and `bench`-label runs post their own results in a sticky comment; they do **not** modify these files.
