#!/usr/bin/env bash

set -euo pipefail

: "${PLATFORM:?PLATFORM is required}"
: "${CONFIG_PATH:?CONFIG_PATH is required}"
: "${DEVICE_PROFILE:?DEVICE_PROFILE is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

device_name_override="${DEVICE_NAME_OVERRIDE:-}"
os_version_override="${OS_VERSION_OVERRIDE:-}"

if [ -n "$device_name_override" ] && [ -n "$os_version_override" ]; then
  echo "device_name=${device_name_override}" >> "$GITHUB_OUTPUT"
  echo "os_version=${os_version_override}" >> "$GITHUB_OUTPUT"
  echo "Using custom ${PLATFORM} device: ${device_name_override} (${os_version_override})"
  exit 0
fi

output=$(cargo-mobench devices resolve \
  --platform "$PLATFORM" \
  --config "$CONFIG_PATH" \
  --profile "$DEVICE_PROFILE" \
  --format json 2>&1) || {
    echo "::error::Failed to resolve ${PLATFORM} device: $output"
    exit 1
  }

device_name=$(echo "$output" | jq -er '.device // .name // .devices[0].name // .devices[0].device') || {
  echo "::error::Failed to parse ${PLATFORM} device name from mobench output: $output"
  exit 1
}

os_version=$(echo "$output" | jq -er '.os_version // .devices[0].os_version') || {
  echo "::error::Failed to parse ${PLATFORM} OS version from mobench output: $output"
  exit 1
}

echo "device_name=${device_name}" >> "$GITHUB_OUTPUT"
echo "os_version=${os_version}" >> "$GITHUB_OUTPUT"
echo "Resolved ${PLATFORM} device: ${device_name} (${os_version})"
