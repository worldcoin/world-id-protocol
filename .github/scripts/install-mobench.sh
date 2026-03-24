#!/usr/bin/env bash

set -euo pipefail

mobench_ref="${MOBENCH_REF:-}"
mobench_version="${MOBENCH_VERSION:-}"

if [ -n "$mobench_ref" ]; then
  if [[ "$mobench_ref" == refs/heads/* ]]; then
    mobench_ref_flag=(--branch "${mobench_ref#refs/heads/}")
  elif [[ "$mobench_ref" == refs/tags/* ]]; then
    mobench_ref_flag=(--tag "${mobench_ref#refs/tags/}")
  elif [[ "$mobench_ref" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
    mobench_ref_flag=(--rev "$mobench_ref")
  else
    mobench_ref_flag=(--branch "$mobench_ref")
  fi

  cargo install mobench \
    --git https://github.com/worldcoin/mobile-bench-rs \
    "${mobench_ref_flag[@]}" \
    --locked
elif [ -n "$mobench_version" ]; then
  cargo install mobench --version "$mobench_version" --locked
else
  cargo install mobench --locked
fi
