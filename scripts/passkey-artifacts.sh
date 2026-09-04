#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
native_dir="$repo_root/crates/proof/noir/passkey-ownership-proof/artifacts"
manifest="$repo_root/artifacts/passkey-artifacts.sha256"

artifact_paths=(
  "crates/proof/noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkp"
  "crates/proof/noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkv"
  "apps/passkey-demo/artifacts/passkey_ownership_proof.pkp"
  "apps/passkey-demo/artifacts/passkey_ownership_proof.pkv"
)

# Binding the generated files to every circuit source makes a source-only
# change fail verification until both artifact lanes are regenerated.
source_paths=(
  "crates/proof/noir/passkey-ownership-proof/Nargo.toml"
  "crates/proof/noir/passkey-ownership-proof/src/commitment.nr"
  "crates/proof/noir/passkey-ownership-proof/src/constants.nr"
  "crates/proof/noir/passkey-ownership-proof/src/main.nr"
  "crates/proof/noir/passkey-ownership-proof/src/merkle_proof.nr"
  "crates/proof/noir/passkey-ownership-proof/src/types.nr"
  "crates/proof/noir/passkey-ownership-proof/src/webauthn.nr"
  "apps/passkey-demo/prepare-browser-artifacts.sh"
  "scripts/passkey-artifacts.sh"
)

fail() {
  echo "error: $*" >&2
  exit 1
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

require_builder() {
  local label=$1 path=$2 expected_commit=$3
  [[ -d "$path/.git" || -f "$path/.git" ]] || fail "$label is not a git checkout: $path"
  local actual_commit
  actual_commit=$(git -C "$path" rev-parse HEAD)
  [[ "$actual_commit" == "$expected_commit" ]] || \
    fail "$label commit is $actual_commit; expected $expected_commit"
  [[ -z "$(git -C "$path" status --porcelain --untracked-files=no)" ]] || \
    fail "$label has tracked changes"
}

prepare_native() {
  : "${PROVEKIT_NATIVE_BUILDER:?set PROVEKIT_NATIVE_BUILDER to a clean worldfnd/provekit checkout at 9b2a6f37c67691eab4b0cec6c35e35c520e93285}"
  : "${NARGO_NATIVE_BIN:?set NARGO_NATIVE_BIN to nargo 1.0.0-beta.11}"
  [[ -x "$NARGO_NATIVE_BIN" ]] || fail "native nargo is not executable: $NARGO_NATIVE_BIN"
  require_builder "native ProveKit builder" "$PROVEKIT_NATIVE_BUILDER" \
    9b2a6f37c67691eab4b0cec6c35e35c520e93285
  local nargo_version
  nargo_version=$("$NARGO_NATIVE_BIN" --version)
  [[ "$nargo_version" == *"1.0.0-beta.11"* ]] || fail "native nargo must be 1.0.0-beta.11"
  [[ "$nargo_version" == *"fd3925aaaeb76c76319f44590d135498ef41ea6c"* ]] || \
    fail "native nargo compiler revision must be fd3925aaaeb76c76319f44590d135498ef41ea6c"

  (
    cd "$PROVEKIT_NATIVE_BUILDER"
    cargo build --locked --release -p provekit-cli --target-dir "$PROVEKIT_NATIVE_BUILDER/target"
  )
  local provekit_native_cli="$PROVEKIT_NATIVE_BUILDER/target/release/provekit-cli"
  [[ -x "$provekit_native_cli" ]] || fail "native provekit-cli build produced no executable"

  (
    cd "$repo_root/crates/proof/noir/passkey-ownership-proof"
    "$NARGO_NATIVE_BIN" fmt --check
    "$NARGO_NATIVE_BIN" test
    "$provekit_native_cli" prepare --skip-brillig-constraints-check --force \
      -p "$native_dir/passkey_ownership_proof.pkp" \
      -v "$native_dir/passkey_ownership_proof.pkv" \
      .
  )
}

install_browser_nargo() {
  local install_dir=${2:-}
  [[ -n "$install_dir" ]] || fail "usage: $0 install-browser-nargo DIR"
  [[ ! -e "$install_dir" ]] || fail "install directory already exists: $install_dir"
  mkdir -p "$install_dir/bin"
  NARGO_HOME="$install_dir" "$HOME/.nargo/bin/noirup" --version 1.0.0-beta.20
  [[ -x "$install_dir/bin/nargo" ]] || fail "noirup did not install nargo"
  "$install_dir/bin/nargo" --version
  echo "use NARGO_BIN=$install_dir/bin/nargo"
}

write_manifest() {
  mkdir -p "$(dirname "$manifest")"
  local tmp_manifest
  tmp_manifest=$(mktemp "${TMPDIR:-/tmp}/passkey-artifacts.sha256.XXXXXX")
  trap 'rm -f "$tmp_manifest"' EXIT
  {
    echo "# Native: worldfnd/provekit 9b2a6f37c67691eab4b0cec6c35e35c520e93285, nargo 1.0.0-beta.11 (noirc fd3925aaaeb76c76319f44590d135498ef41ea6c)"
    echo "# Browser: worldfnd/provekit 4b61b5d68e633a044eb41de4a6934d52ffdcbedc, nargo 1.0.0-beta.20 (noirc b4236c1957d0c26cb65d82adc9e5447b6ff1d629)"
  } >> "$tmp_manifest"
  for path in "${source_paths[@]}" "${artifact_paths[@]}"; do
    [[ -f "$repo_root/$path" ]] || fail "missing manifest input: $path"
    printf '%s  %s\n' "$(sha256_file "$repo_root/$path")" "$path" >> "$tmp_manifest"
  done
  mv "$tmp_manifest" "$manifest"
  trap - EXIT
  echo "wrote $manifest"
}

verify_manifest() {
  [[ -f "$manifest" ]] || fail "missing manifest: $manifest (run '$0 write-manifest' after regenerating both lanes)"
  (
    cd "$repo_root"
    shasum -a 256 --check "$manifest"
  )
}

case "${1:-}" in
  prepare-native) prepare_native ;;
  prepare-browser) "$repo_root/apps/passkey-demo/prepare-browser-artifacts.sh" ;;
  install-browser-nargo) install_browser_nargo "$@" ;;
  write-manifest) write_manifest ;;
  verify) verify_manifest ;;
  *)
    echo "usage: $0 {prepare-native|prepare-browser|install-browser-nargo DIR|write-manifest|verify}" >&2
    exit 2
    ;;
esac
