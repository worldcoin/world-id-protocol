#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
source_dir="$repo_root/crates/proof/noir/passkey-ownership-proof"
expected_builder_commit=4b61b5d68e633a044eb41de4a6934d52ffdcbedc
expected_nargo_version=1.0.0-beta.20
expected_noirc_commit=b4236c1957d0c26cb65d82adc9e5447b6ff1d629

: "${PROVEKIT_BROWSER_BUILDER:?set PROVEKIT_BROWSER_BUILDER to a clean worldfnd/provekit checkout at $expected_builder_commit}"
: "${NARGO_BIN:?set NARGO_BIN to the nargo $expected_nargo_version binary}"

provekit_cli="$PROVEKIT_BROWSER_BUILDER/target/release/provekit-cli"

fail() {
  echo "error: $*" >&2
  exit 1
}

[[ -x "$NARGO_BIN" ]] || fail "NARGO_BIN is not executable: $NARGO_BIN"
[[ -d "$PROVEKIT_BROWSER_BUILDER/.git" || -f "$PROVEKIT_BROWSER_BUILDER/.git" ]] || \
  fail "browser builder is not a git checkout: $PROVEKIT_BROWSER_BUILDER"

actual_builder_commit=$(git -C "$PROVEKIT_BROWSER_BUILDER" rev-parse HEAD)
[[ "$actual_builder_commit" == "$expected_builder_commit" ]] || \
  fail "browser builder commit is $actual_builder_commit; expected $expected_builder_commit"
[[ -z "$(git -C "$PROVEKIT_BROWSER_BUILDER" status --porcelain --untracked-files=no)" ]] || \
  fail "browser builder has tracked changes"

nargo_version=$("$NARGO_BIN" --version)
[[ "$nargo_version" == *"$expected_nargo_version"* ]] || \
  fail "nargo version is '$nargo_version'; expected $expected_nargo_version"
[[ "$nargo_version" == *"$expected_noirc_commit"* ]] || \
  fail "nargo compiler revision is not $expected_noirc_commit: '$nargo_version'"

# Build from the reviewed, locked source revision instead of trusting a
# machine-specific prebuilt executable.
(
  cd "$PROVEKIT_BROWSER_BUILDER"
  cargo build --locked --release -p provekit-cli --target-dir "$PROVEKIT_BROWSER_BUILDER/target"
)
[[ -x "$provekit_cli" ]] || fail "browser provekit-cli build produced no executable"

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/passkey-browser-circuit.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
cp -R "$source_dir/." "$build_dir"

# The browser SDK consumes PKP 2.0 / PKV 2.1, whose compiler requires the
# beta.20-compatible releases of the same Noir libraries and their renamed
# Poseidon entry points. The proof statement and all other source stay shared.
perl -pi -e 's/v0\.5\.0-beta\.0/v0.6.1/; s/v0\.8\.0/v0.10.0/; s/v0\.11\.0/v0.14.0/; s/v0\.2\.1/v0.3.0/' "$build_dir/Nargo.toml"
perl -pi -e 's/poseidon2::bn254::perm/poseidon2::bn254::permutation/; s/perm::x5_16/permutation::t16/g' "$build_dir/src/commitment.nr"
perl -pi -e 's/poseidon2::bn254::perm/poseidon2::bn254::permutation/; s/perm::x5_2/permutation::t2/g' "$build_dir/src/merkle_proof.nr"
perl -pi -e 's/\.len\(\) as u64/.len()/g' "$build_dir/src/webauthn.nr"
perl -pi -e 's/origin_len as u64/origin_len/g' "$build_dir/src/webauthn.nr"

(
  cd "$build_dir"
  "$NARGO_BIN" fmt --check
  "$NARGO_BIN" test
  "$provekit_cli" prepare --skip-brillig-constraints-check --force \
    -p "$repo_root/apps/passkey-demo/artifacts/passkey_ownership_proof.pkp" \
    -v "$repo_root/apps/passkey-demo/artifacts/passkey_ownership_proof.pkv" \
    .
)
