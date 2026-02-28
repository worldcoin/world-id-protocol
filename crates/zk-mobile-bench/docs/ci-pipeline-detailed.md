# Mobile Bench CI Pipeline (Detailed)

This document describes the PR-focused mobile benchmark CI flow.

Scope:
- BrowserStack iOS + Android benchmark execution
- PR-triggered runs via `/mobench ...`
- Manual runs via `workflow_dispatch`
- Result summarization and PR reporting

## 1. Pipeline architecture

The CI uses a **thin caller workflow** in this repository that delegates all heavy
lifting to a reusable workflow from `worldcoin/mobile-bench-rs`.

Workflow files:
- `.github/workflows/mobile-bench.yml` -- thin caller (~67 lines)
- `.github/workflows/mobile-bench-pr-command.yml` -- PR comment dispatch

The caller workflow invokes:
```
worldcoin/mobile-bench-rs/.github/workflows/reusable-bench.yml@v0.1.15
```

This replaces the previous ~1064-line monolithic workflow. All build, execution,
artifact handling, and summarization logic now lives in the reusable workflow.

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
- Others are rejected with a PR comment explaining restriction

Branch scope:
- Dispatch from fork PRs is blocked
- Only PRs whose head repo is the same repository are allowed

### 2.2 Manual trigger

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
- `requested_by` (string, optional; shown in summary metadata)

The following parameters from the old workflow have been removed:
- `proof_scope`, `modes`, `mobench_ref`, `fetch_timeout_secs`, `also_bench_query`

Validation performed in command workflow:
- unknown keys are rejected
- enum values are validated
- numeric values are validated as integers with minimum constraints
- custom device profile requires matching device + os_version keys

## 4. Reusable workflow contract

The caller passes these to the reusable workflow:

- `crate_path`: `"crates/zk-mobile-bench"`
- `platform`, `device_profile`, device overrides, `iterations`, `warmup`
- `pr_number`, `requested_by`
- `functions`: JSON array of benchmark function names to run

The `functions` list is specified directly in the caller workflow:
```json
["bench_nullifier_proof_generation","bench_nullifier_witness_generation_only","bench_nullifier_proving_only","bench_query_proof_generation","bench_query_witness_generation_only","bench_query_proving_only"]
```

Secrets are passed via `secrets: inherit`.

## 5. Result summarization

Summarization is handled by the `mobench` CLI (not a Python script):

- **`mobench ci summarize`**: Parses benchmark JSON/CSV artifacts and renders a
  markdown summary table. Output is published to `GITHUB_STEP_SUMMARY` and optionally
  as a sticky PR comment (`<!-- mobench-summary -->`).

- **`mobench ci check-run`**: When a GitHub App is configured, publishes results as
  GitHub Check Runs on the commit.

This replaces the previous `crates/zk-mobile-bench/scripts/summarize_mobench_ci.py`.

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
- `.github/workflows/mobile-bench-pr-command.yml` (input schema + validation)
- `.github/workflows/mobile-bench.yml` (caller inputs + reusable workflow version)
- `crates/zk-mobile-bench/docs/ci-browserstack.md` and this document

To update the reusable workflow version, change the `@v0.1.15` tag in `mobile-bench.yml`.
