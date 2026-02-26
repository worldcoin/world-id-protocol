# CI / BrowserStack

## Architecture

The benchmark CI uses a thin caller workflow in this repository that delegates to a
reusable workflow from `worldcoin/mobile-bench-rs`:

- `.github/workflows/mobile-bench.yml` (~67 lines) -- caller workflow
- `.github/workflows/mobile-bench-pr-command.yml` -- PR comment trigger

The caller workflow invokes:
```
worldcoin/mobile-bench-rs/.github/workflows/reusable-bench.yml@v0.1.15
```

All build, run, summarization, and reporting logic lives in the reusable workflow.

## Triggers

- **Manual**: `workflow_dispatch` on `mobile-bench.yml`
- **PR comment**: `/mobench ...` via `mobile-bench-pr-command.yml`

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

When a GitHub App is configured, `mobench ci check-run` can also publish results as
GitHub Check Runs on the commit.
