#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
source_dir="$repo_root/crates/proof/noir/passkey-ownership-proof"
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

(
  cd "$build_dir"
  nargo fmt --check
  nargo test
  provekit-cli prepare --skip-brillig-constraints-check --force \
    -p "$repo_root/apps/passkey-demo/artifacts/passkey_ownership_proof.pkp" \
    -v "$repo_root/apps/passkey-demo/artifacts/passkey_ownership_proof.pkv" \
    .
)
