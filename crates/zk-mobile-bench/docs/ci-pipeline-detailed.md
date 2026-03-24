# Mobile Bench CI Pipeline (Detailed)

This document describes the PR-focused mobile benchmark CI flow.

Scope:
- BrowserStack iOS + Android benchmark execution
- PR-triggered runs via `/mobench ...`
- Manual runs via `workflow_dispatch`
- Result summarization and PR reporting

## 1. Pipeline architecture

The CI now uses a **vendored stateless mobench controller flow** in this repository.

Workflow files:
- `.github/workflows/compile-gate.yml` -- compile gate for PR SHAs
- `.github/workflows/mobile-bench-after-ci.yml` -- dispatch benchmark runs after compile gate success
- `.github/workflows/mobile-bench-pr-auto.yml` -- `bench` label auto-dispatch
- `.github/workflows/mobile-bench-pr-command.yml` -- trusted `/mobench ...` dispatch
- `.github/workflows/mobile-bench.yml` -- stateless benchmark runner
- `.github/workflows/reusable-bench.yml` -- BrowserStack build/run/summarize implementation

The controller and runner are adapted from the `mobench` 0.1.18 stateless flow, with
World ID-specific benchmark functions and crate-scoped bench configs.
Repeated CLI operations are delegated to repo-local helper scripts:

- `.github/scripts/install-mobench.sh`
- `.github/scripts/resolve-mobench-device.sh`
- `.github/scripts/run-mobench-benchmarks.sh`
- `.github/scripts/summarize-mobench-platform.sh`

## 2. Trigger model

### 2.1 PR comment trigger (primary)

Workflow: `.github/workflows/mobile-bench-pr-command.yml`

Event: `issue_comment` (`created`)

Command format:
```text
/mobench key=value key2=value2 ...
```

Authorization:
- Allowed associations: `OWNER`, `MEMBER`, `COLLABORATOR`
- Others are ignored

Branch scope:
- Dispatch from fork PRs is blocked
- Only PRs whose head repo is the same repository are allowed
- Dispatch waits for `compile-gate.yml` to succeed for the exact PR `head_sha`

### 2.2 Bench label auto trigger

Workflow: `.github/workflows/mobile-bench-pr-auto.yml`

Event: `pull_request_target` (`labeled`)

Behavior:
- Only the `bench` label is honored
- Dispatch is limited to same-repo PRs
- Dispatch only happens once `compile-gate.yml` has already passed for the current `head_sha`

### 2.3 Manual trigger

Workflow: `.github/workflows/mobile-bench.yml`

Event: `workflow_dispatch`

Use this when:
- you want a run without PR comment dispatch
- you want to run ad hoc with direct input editing in Actions UI

## 3. Input contract

These inputs are accepted by `mobile-bench.yml`:

- `platform` (`both` | `ios` | `android`, default `both`)
- `iterations` (number, default `30`)
- `warmup` (number, default `5`)
- `device_profile` (`low-spec` | `mid-spec` | `high-spec` | `custom`, default `low-spec`)
- `ios_device` (string, optional; required for iOS when `device_profile=custom`)
- `ios_os_version` (string, optional; required for iOS when `device_profile=custom`)
- `android_device` (string, optional; required for Android when `device_profile=custom`)
- `android_os_version` (string, optional; required for Android when `device_profile=custom`)
- `pr_number` (string, optional; enables sticky PR summary comment)
- `base_ref` (string, optional; baseline metadata)
- `head_sha` (string, optional; exact commit to benchmark)
- `requested_by` (string, optional; shown in summary metadata)
- `dispatch_id`, `trigger_source`, `request_command` (optional controller metadata)
- `mobench_version` (default `0.1.18`)
- `mobench_ref` (optional override for installing from git)
- `check_run_name` (default `Mobench`)
- `regression_threshold_pct` (default `5.0`)

PR comment parsing still only accepts the runtime overrides:
- `platform`
- `iterations`
- `warmup`
- `device_profile`
- `ios_device`, `ios_os_version`
- `android_device`, `android_os_version`

## 4. Reusable workflow contract

The caller passes these to the reusable workflow:

- `crate_path`: `"crates/zk-mobile-bench"`
- `platform`, `device_profile`, device overrides, `iterations`, `warmup`
- `pr_number`, `base_ref`, `head_sha`, `requested_by`
- controller metadata: `dispatch_id`, `trigger_source`, `request_command`
- `mobench_version`, `mobench_ref`, `check_run_name`, `regression_threshold_pct`
- `functions`: JSON array of benchmark function names to run

The `functions` list is specified directly in the caller workflow:
```json
["zk_mobile_bench::bench_nullifier_proof_generation","zk_mobile_bench::bench_nullifier_witness_generation_only","zk_mobile_bench::bench_nullifier_proving_only","zk_mobile_bench::bench_query_proof_generation","zk_mobile_bench::bench_query_proof_only","zk_mobile_bench::bench_query_witness_generation_only","zk_mobile_bench::bench_query_proving_only"]
```

Device resolution uses the crate-local configs:
- `crates/zk-mobile-bench/bench-config.ios.toml`
- `crates/zk-mobile-bench/bench-config.android.toml`

## 5. Result summarization

Summarization is handled by the `mobench` CLI (not a Python script):

- **`mobench ci summarize`**: Parses benchmark JSON/CSV artifacts and renders a
  markdown summary table. Output is published to `GITHUB_STEP_SUMMARY` and optionally
  as a sticky PR comment (`<!-- mobench-summary -->`).

In this repository, the reusable workflow calls
`.github/scripts/summarize-mobench-platform.sh`, which wraps those `cargo-mobench`
summary commands for both platforms.

This replaces the previous `crates/zk-mobile-bench/scripts/summarize_mobench_ci.py` flow
and uploads a canonical history bundle pinned to the benchmarked `head_sha`.

## 6. Common usage patterns

Default broad run:
```text
/mobench platform=both iterations=30 warmup=5 device_profile=low-spec
```

iOS-only run:
```text
/mobench platform=ios iterations=20 warmup=3 device_profile=low-spec
```

Custom explicit devices:
```text
/mobench platform=both device_profile=custom ios_device="iPhone 11" ios_os_version="13" android_device="Google Pixel 6" android_os_version="12"
```

## 7. Permissions and security posture

Command workflow permissions:
- `contents: read`
- `actions: write` (dispatch workflow)
- `issues: write` (feedback comments)
- `pull-requests: read`

Security controls:
- collaborator-only trigger authorization
- fork PR dispatch blocked for secrets safety
- strict typed input validation (no raw passthrough arg execution)

## 8. Failure handling behavior

Key behavior:
- reusable workflow handles partial failures and summarization
- missing artifacts are tolerated and reported
- PR comment is skipped safely when `pr_number` missing/invalid
- existing summary comment is updated instead of posting duplicates

## 9. Operational maintenance notes

When updating pipeline behavior, keep these aligned:
- `.github/workflows/compile-gate.yml`
- `.github/workflows/mobile-bench-after-ci.yml`
- `.github/workflows/mobile-bench-pr-auto.yml`
- `.github/workflows/mobile-bench-pr-command.yml`
- `.github/workflows/mobile-bench.yml`
- `.github/workflows/reusable-bench.yml`
- `.github/scripts/mobench-controller.mjs`
- `.github/scripts/install-mobench.sh`
- `.github/scripts/resolve-mobench-device.sh`
- `.github/scripts/run-mobench-benchmarks.sh`
- `.github/scripts/summarize-mobench-platform.sh`
- `crates/zk-mobile-bench/docs/ci-browserstack.md` and this document
