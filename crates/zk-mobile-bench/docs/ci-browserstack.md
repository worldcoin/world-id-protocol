# CI / BrowserStack

## Architecture

The benchmark CI now uses the vendored stateless `mobench` 0.1.16 workflow set in this repository:

- `.github/workflows/compile-gate.yml` -- compile gate for exact PR SHAs
- `.github/workflows/mobile-bench-after-ci.yml` -- dispatch after compile gate success
- `.github/workflows/mobile-bench-pr-auto.yml` -- `bench` label auto-dispatch
- `.github/workflows/mobile-bench-pr-command.yml` -- trusted `/mobench ...` PR command
- `.github/workflows/mobile-bench.yml` -- stateless benchmark runner
- `.github/workflows/reusable-bench.yml` -- reusable BrowserStack execution workflow

The workflow files are adapted from the `mobench` 0.1.16 stateless controller flow and
use crate-local benchmark configs under `crates/zk-mobile-bench/`.

## Triggers

- **Manual**: `workflow_dispatch` on `mobile-bench.yml`
- **PR comment**: trusted `/mobench ...` via `mobile-bench-pr-command.yml`
- **PR label**: apply the `bench` label after compile gate passes

## Parameters

- `platform`: `both` | `ios` | `android`
- `iterations`: measured iteration count
- `warmup`: warmup iteration count
- `device_profile`: `low-spec` | `mid-spec` | `high-spec` | `custom`
- custom overrides:
  - `ios_device`, `ios_os_version`
  - `android_device`, `android_os_version`

## PR command examples

Run both platforms with low-spec profile:

```text
/mobench platform=both iterations=30 warmup=5 device_profile=low-spec
```

Run only iOS:

```text
/mobench platform=ios iterations=20 warmup=3 device_profile=low-spec
```

Use explicit devices:

```text
/mobench platform=both device_profile=custom ios_device="iPhone 11" ios_os_version="13" android_device="Google Pixel 6" android_os_version="12"
```

## Required repository secrets

- `BROWSERSTACK_USERNAME`
- `BROWSERSTACK_ACCESS_KEY`

## Result reporting

The reusable workflow handles summarization via `mobench ci summarize`, which:
- Parses benchmark JSON/CSV artifacts
- Renders a markdown summary table
- Publishes to `GITHUB_STEP_SUMMARY`
- Posts/updates a sticky PR comment (`<!-- mobench-summary -->`) when `pr_number` is set

The stateless workflow also records `head_sha`, trigger metadata, and resolved device
information in the uploaded history bundle so runs stay pinned to the compile-gated commit.
