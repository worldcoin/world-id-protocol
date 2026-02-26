# Mobile Bench CI Pipeline (Detailed)

This document describes the current PR-focused mobile benchmark CI flow in detail.

Scope:
- BrowserStack iOS + Android benchmark execution
- PR-triggered runs via `/mobench ...`
- Manual runs via `workflow_dispatch`
- Natural-language result interpretation in CI summary and sticky PR comment

Out of scope:
- GitHub App integration (not used in v1)
- Automatic per-commit benchmark triggering

## 1. Pipeline architecture

Primary workflow files:
- `.github/workflows/mobile-bench-pr-command.yml`
- `.github/workflows/mobile-bench-ios.yml`
- `.github/workflows/mobile-bench-pr-label.yml` (legacy, intentionally disabled)

Helper script:
- `crates/zk-mobile-bench/scripts/summarize_mobench_ci.py`

Main data flow:
1. User comments `/mobench ...` on a PR.
2. Command workflow validates auth and parameters.
3. Command workflow dispatches `mobile-bench-ios.yml` on the PR head branch.
4. iOS and/or Android jobs run based on `platforms`.
5. Artifacts (JSON/CSV + runtime TOML configs) are uploaded.
6. Final `summarize` job parses artifacts and writes a natural-language summary.
7. Summary is published to:
- GitHub Actions job summary (`GITHUB_STEP_SUMMARY`)
- sticky PR comment (`<!-- mobench-summary -->`) when `pr_number` is provided

## 2. Trigger model

## 2.1 PR comment trigger (primary)

Workflow:
- `.github/workflows/mobile-bench-pr-command.yml`

Event:
- `issue_comment` (`created`)

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

## 2.2 Manual trigger

Workflow:
- `.github/workflows/mobile-bench-ios.yml`

Event:
- `workflow_dispatch`

Use this when:
- you want a run without PR comment dispatch
- you want to run ad hoc with direct input editing in Actions UI

## 2.3 Legacy label trigger

Workflow:
- `.github/workflows/mobile-bench-pr-label.yml`

Status:
- intentionally disabled as auto-trigger mechanism
- now `workflow_dispatch` only with a no-op explanatory job

Reason:
- avoid expensive benchmark runs on every PR push (`synchronize`)

## 3. Input contract

These inputs are accepted by `mobile-bench-ios.yml` (`workflow_dispatch` and `workflow_call`):

- `mobench_ref` (string, default `codex/ci-devex`)
- `iterations` (number, default `30`)
- `warmup` (number, default `5`)
- `fetch_timeout_secs` (number, default `1800`)
- `platforms` (`both` | `ios` | `android`, default `both`)
- `proof_scope` (`both` | `pi2` | `pi1`, default `both`)
- `modes` (`all` or comma list of `witness,proving,full`, default `all`)
- `device_profile` (`low-spec` | `mid-spec` | `high-spec` | `auto-low-spec` | `custom`, default `low-spec`)
- `ios_device` (string, optional; required for iOS when `device_profile=custom`)
- `ios_os_version` (string, optional; required for iOS when `device_profile=custom`)
- `android_device` (string, optional; required for Android when `device_profile=custom`)
- `android_os_version` (string, optional; required for Android when `device_profile=custom`)
- `pr_number` (string, optional; enables sticky PR summary comment)
- `requested_by` (string, optional; shown in summary metadata)
- `request_command` (string, optional; shown in summary metadata)
- `also_bench_query` (deprecated; ignored by main selection logic)

Validation performed in command workflow:
- unknown keys are rejected
- enum values are validated
- numeric values are validated as integers with minimum constraints
- `modes=all` cannot be combined with other modes
- custom device profile requires matching device + os_version keys

## 4. Mobench source selection

`mobile-bench-rs` checkout uses:
- repository: `worldcoin/mobile-bench-rs`
- ref: `${{ inputs.mobench_ref }}`

Default remains:
- `codex/ci-devex`

This allows PR comments like:
```text
/mobench mobench_ref=codex/ci-devex platforms=both proof_scope=both modes=all device_profile=auto-low-spec
```

## 5. Job execution details

## 5.1 iOS job (`ios-browserstack`)

High-level steps:
1. Checkout `world-id-protocol`.
2. Checkout `mobile-bench-rs` at `inputs.mobench_ref`.
3. Patch mobench BrowserStack device endpoint to `app-automate/devices.json`.
4. Setup Rust + iOS targets.
5. Install XcodeGen and local `cargo-mobench`.
6. Resolve iOS device from BrowserStack device list (profile/custom logic).
7. Write runtime iOS config (`crates/zk-mobile-bench/bench-config.ios.runtime*.toml`).
8. Build iOS BrowserStack artifacts:
- `target/mobench/ios/BenchRunner.ipa`
- `target/mobench/ios/BenchRunnerUITests.zip`
9. Run selected benchmarks (`proof_scope` + `modes` selection).
10. Upload iOS artifacts:
- `target/mobench/ci/ios/*.json`
- `target/mobench/ci/ios/*.csv`
- `target/browserstack/**`
- `crates/zk-mobile-bench/bench-config.ios.runtime*.toml`

## 5.2 Android job (`android-browserstack`)

High-level steps:
1. Checkout `world-id-protocol`.
2. Checkout `mobile-bench-rs` at `inputs.mobench_ref`.
3. Apply same BrowserStack endpoint patch.
4. Setup Rust + Android SDK/NDK and required targets.
5. Install local `cargo-mobench`.
6. Resolve Android device from BrowserStack device list (profile/custom logic).
7. Write runtime Android config (`crates/zk-mobile-bench/bench-config.android.runtime*.toml`).
8. Run selected benchmarks (`proof_scope` + `modes` selection).
9. Upload Android artifacts:
- `target/mobench/ci/android/*.json`
- `target/mobench/ci/android/*.csv`
- `target/browserstack/**`
- `crates/zk-mobile-bench/bench-config.android.runtime*.toml`

## 5.3 Benchmark selection mechanics

Both platform jobs apply the same scope/mode filtering to this logical set:
- `pi2`: `witness`, `proving`, `full`
- `pi1`: `witness`, `proving`, `full`

If filtering produces no selected benches:
- the job fails with explicit selection error

## 6. Result interpretation and publication

`summarize` job:
- runs on `ubuntu-latest`
- `needs: [ios-browserstack, android-browserstack]`
- `if: always()` so it runs even on partial failures

Steps:
1. Checkout repo (for summary script).
2. Download iOS artifact (`if-no-artifact-found: ignore`).
3. Download Android artifact (`if-no-artifact-found: ignore`).
4. Run `crates/zk-mobile-bench/scripts/summarize_mobench_ci.py`.
5. Append generated markdown to `GITHUB_STEP_SUMMARY`.
6. If `pr_number` is set, upsert sticky PR comment with marker:
- `<!-- mobench-summary -->`

Summary content includes:
- overall status sentence (success/partial/failure semantics)
- run metadata (run URL, mobench ref, requested inputs)
- platform job status values from `needs.*.result`
- detected device/os from runtime TOML files when available
- parsed CSV metric lines per benchmark output file
- explicit artifact scan roots
- interpretation mode disclaimer:
  - descriptive only (no regression gate, no thresholds)

## 7. Artifacts and expected outputs

iOS artifact name:
- `mobench-ios-results`

Android artifact name:
- `mobench-android-results`

Expected files (per platform):
- `*.json` raw run outputs
- `*.csv` summary outputs
- BrowserStack output folder content
- runtime benchmark config TOML files

## 8. Common usage patterns

Default broad run:
```text
/mobench platforms=both iterations=30 warmup=5 proof_scope=both modes=all device_profile=auto-low-spec
```

iOS-only pi2 proving:
```text
/mobench platforms=ios proof_scope=pi2 modes=proving iterations=20 warmup=3 device_profile=low-spec
```

Custom explicit devices:
```text
/mobench platforms=both device_profile=custom ios_device="iPhone 11" ios_os_version="13" android_device="Google Pixel 6" android_os_version="12"
```

## 9. Permissions and security posture

Command workflow permissions:
- `contents: read`
- `actions: write` (dispatch workflow)
- `issues: write` (feedback comments)
- `pull-requests: read`

Main benchmark workflow permissions:
- `contents: read`
- summary job additionally uses:
  - `issues: write`
  - `pull-requests: read`

Security controls:
- collaborator-only trigger authorization
- fork PR dispatch blocked for secrets safety
- strict typed input validation (no raw passthrough arg execution)

## 10. Failure handling behavior

Key behavior:
- summary job still runs on partial failures
- missing artifacts are tolerated and reported as partial visibility
- PR comment is skipped safely when `pr_number` missing/invalid
- existing summary comment is updated instead of posting duplicates

Typical failure surfaces:
- invalid `/mobench` params -> immediate command rejection comment
- BrowserStack/device mismatch -> platform job failure + partial summary
- benchmark build/runtime failure on one platform -> partial summary with surviving platform metrics

## 11. Operational maintenance notes

When updating pipeline behavior, keep these aligned:
- `.github/workflows/mobile-bench-pr-command.yml` (input schema + validation)
- `.github/workflows/mobile-bench-ios.yml` (actual input declarations + job logic)
- `crates/zk-mobile-bench/scripts/summarize_mobench_ci.py` (reporting format and parser logic)
- `crates/zk-mobile-bench/docs/ci-browserstack.md` and this document

If new benchmark outputs change CSV schema:
- update parser metric candidate mapping in `summarize_mobench_ci.py`
- keep parser tolerant to schema drift (do not hard-fail summary generation)
