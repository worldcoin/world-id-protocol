# Joint Mobench Plot Rendering Design

Date: 2026-03-26

## Goal

Render one shared set of Sina-style device comparison plots across all successful benchmark devices in a CI run, while keeping the benchmark tables split by OS in the GitHub Actions summary and sticky PR comment.

## Current State

- The reusable workflow renders iOS and Android summaries independently.
- Each per-platform markdown summary includes its own `Device Comparison Plots` section.
- The sticky PR comment is assembled by concatenating the iOS markdown and Android markdown files.
- This means dual-platform runs produce separate plot sections instead of one joint comparison view.

## Approved Approach

Use a workflow-local combined plot pipeline layered on top of the existing per-platform summaries.

### OS Tables

- Keep the current iOS and Android summary generation for tables.
- Keep the current OS-specific section structure in the Actions summary and sticky PR comment.
- Remove the `Device Comparison Plots` block from the per-platform markdown before publishing so the tables remain OS-scoped.

### Shared Plot Section

- Build a synthetic combined summary JSON from the successful per-platform root `summary.json` files.
- Preserve the `mobench` summary schema fields needed by `cargo-mobench report summarize`.
- Concatenate `summary.device_summaries` from iOS and Android into one combined plot-only summary.
- Use deterministic device ordering: iOS devices first, then Android devices.
- Render the shared plot markdown from the combined summary, then append that markdown once after both OS table sections.

### Device Chunking

- If the combined device count is 6 or fewer, generate one plot per function.
- If the combined device count is greater than 6, split devices into consecutive chunks of at most 6 devices.
- For each function, render multiple images back-to-back when chunking is needed.
- Do not add chunk titles such as `Devices 1-6`; the visual cutoff is sufficient.

## Output Shape

The final GitHub Actions summary and sticky PR comment should be ordered as:

1. `## iOS Benchmark Results` with iOS tables only
2. `## Android Benchmark Results` with Android tables only
3. One shared `## Device Comparison Plots` section containing all combined-device Sina plots

If only one platform succeeds, the shared plot section should still render from that platform's devices.

## Failure Behavior

- If per-platform table rendering succeeds but combined plot rendering fails, keep the tables and omit the shared plot section.
- Plot rendering failure must not fail the entire summarize job.
- Plot asset publishing should only run when there are rendered SVGs to upload.

## Artifact / History Expectations

- Preserve the per-platform rendered markdown files in the history bundle.
- Preserve the combined plot markdown fragment in the history bundle.
- Preserve the combined plot SVG assets in the published `mobench-plots` branch structure for the run.

## Scope

In scope:

- `.github/workflows/mobile-bench-reusable.yml`
- Workflow-local JSON and markdown shaping for combined plots

Out of scope:

- Upstream `mobench` feature work
- Changing benchmark table layout beyond removing per-OS plot sections
- Changing device resolution behavior

## Verification

- `actionlint` for workflow syntax
- An iOS-only run to verify the shared plot section still works with one platform
- A dual-platform run to verify:
  - separate iOS and Android table sections
  - one shared plot section
  - chunking behavior when the combined device count exceeds 6
- History bundle inspection to confirm the combined plot fragment was archived
