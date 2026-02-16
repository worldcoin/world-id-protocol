# CI / BrowserStack

The benchmark workflow is:

- `.github/workflows/mobile-bench-ios.yml`

It supports iOS and Android and can be triggered:

- manually (`workflow_dispatch`)
- from PR comments via `/mobench ...` (see `.github/workflows/mobile-bench-pr-command.yml`)
- not from automatic per-commit label/synchronize triggers (legacy label workflow is disabled)

## Default mobench source

`mobench_ref` defaults to:

- `codex/ci-devex` from `worldcoin/mobile-bench-rs`

## Main parameters

- `platforms`: `both` | `ios` | `android`
- `proof_scope`: `both` | `pi2` | `pi1`
- `modes`: `all` or comma list from `witness,proving,full`
- `iterations`: measured iteration count
- `warmup`: warmup iteration count
- `fetch_timeout_secs`
- `device_profile`: `low-spec` | `mid-spec` | `high-spec` | `auto-low-spec` | `custom`
- custom overrides:
  - `ios_device`, `ios_os_version`
  - `android_device`, `android_os_version`

## PR command examples

Run both platforms with low-spec auto selection:

```text
/mobench platforms=both iterations=30 warmup=5 proof_scope=both modes=all device_profile=auto-low-spec
```

Run only `π2` proving on iOS:

```text
/mobench platforms=ios proof_scope=pi2 modes=proving iterations=20 warmup=3 device_profile=low-spec
```

Use explicit devices:

```text
/mobench platforms=both device_profile=custom ios_device="iPhone 11" ios_os_version="13" android_device="Google Pixel 6" android_os_version="12"
```

## Required repository secrets

- `BROWSERSTACK_USERNAME`
- `BROWSERSTACK_ACCESS_KEY`
- optional: `MOBENCH_REPO_TOKEN`

## Trigger and reporting UX

Recommended PR flow:

1. Comment on the PR with `/mobench ...` command parameters.
2. Workflow dispatches against that PR head branch.
3. Results are interpreted in natural language and published in:
- GitHub Actions job summary (`GITHUB_STEP_SUMMARY`)
- a sticky PR comment (`<!-- mobench-summary -->`) that is updated in-place

The benchmark workflow accepts optional metadata inputs used for reporting:

- `pr_number`
- `requested_by`
- `request_command`

These are populated automatically by `.github/workflows/mobile-bench-pr-command.yml`.
