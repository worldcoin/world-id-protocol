#!/usr/bin/env bash

set -euo pipefail

: "${PLATFORM:?PLATFORM is required}"
: "${CRATE_PATH:?CRATE_PATH is required}"
: "${FUNCTIONS_JSON:?FUNCTIONS_JSON is required}"
: "${ITERATIONS:?ITERATIONS is required}"
: "${WARMUP:?WARMUP is required}"
: "${DEVICE_NAME:?DEVICE_NAME is required}"
: "${OS_VERSION:?OS_VERSION is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"

mkdir -p "$OUTPUT_DIR"

device_spec="${DEVICE_NAME}-${OS_VERSION}"
echo "Running ${PLATFORM} benchmarks on: ${device_spec}"

release_flag="${RELEASE_FLAG:-}"
release_args=()
if [ -n "$release_flag" ]; then
  release_args+=("$release_flag")
fi

jq -r '.[]' <<<"$FUNCTIONS_JSON" | while IFS= read -r func; do
  slug=$(echo "$func" | tr ':' '_' | tr '/' '-')
  echo "::group::Benchmark: ${func}"
  cargo-mobench run \
    --target "$PLATFORM" \
    --crate-path "$CRATE_PATH" \
    --function "$func" \
    --iterations "$ITERATIONS" \
    --warmup "$WARMUP" \
    --devices "$device_spec" \
    "${release_args[@]}" \
    --fetch \
    --summary-csv \
    --output "$OUTPUT_DIR/${slug}.json" || {
      echo "::warning::${PLATFORM} benchmark failed for function: ${func}"
    }
  echo "::endgroup::"
done
