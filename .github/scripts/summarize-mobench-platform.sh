#!/usr/bin/env bash

set -euo pipefail

: "${PLATFORM:?PLATFORM is required}"
: "${RESULTS_DIR:?RESULTS_DIR is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"

label="$PLATFORM"
case "$PLATFORM" in
  ios)
    label="iOS"
    ;;
  android)
    label="Android"
    ;;
esac

cargo-mobench ci summarize \
  --results-dir "$RESULTS_DIR" \
  --output-format json \
  --output-file "$RESULTS_DIR/summary.json"

cargo-mobench ci summarize \
  --results-dir "$RESULTS_DIR" \
  --output-format markdown \
  --output-file "$RESULTS_DIR/summary.md"

cargo-mobench summary "$RESULTS_DIR/summary.json" --format csv > "$RESULTS_DIR/results.csv"

cargo-mobench ci summarize \
  --results-dir "$RESULTS_DIR" \
  --output-format table || true

echo "## ${label} Benchmark Results" >> "$GITHUB_STEP_SUMMARY"
echo "" >> "$GITHUB_STEP_SUMMARY"

if [ -f "$RESULTS_DIR/summary.md" ]; then
  cat "$RESULTS_DIR/summary.md" >> "$GITHUB_STEP_SUMMARY"
else
  echo "No ${label} results found." >> "$GITHUB_STEP_SUMMARY"
fi

echo "" >> "$GITHUB_STEP_SUMMARY"
