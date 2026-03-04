# Rust workspace operations.
# Uses PARALLEL_JOBS from the root Justfile.
#
# Lint conventions (project-wide):
#   Format  →  cargo +nightly fmt --all
#   Clippy  →  RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features

# ─────────────────────────────────────────────────────────────────────────────
# cargo · build
# ─────────────────────────────────────────────────────────────────────────────

# Build the workspace in debug mode.
# Example:  just cargo-build
[group('cargo · build')]
cargo-build *args='':
    cargo build --workspace {{ args }}

# Check the workspace compiles without producing artifacts (fast feedback).
# Example:  just cargo-check
[group('cargo · build')]
cargo-check *args='':
    cargo check --workspace --all-features {{ args }}

# Build the workspace in release mode.
# Example:  just cargo-build-release
[group('cargo · build')]
cargo-build-release *args='':
    cargo build --workspace --release {{ args }}

# Generate rustdoc for the entire workspace.
# Example:  just cargo-doc
[group('cargo · build')]
cargo-doc *args='':
    cargo doc --workspace --document-private-items {{ args }}

# Remove Rust build artifacts (target/).
# Example:  just cargo-clean
[group('cargo · build')]
cargo-clean:
    cargo clean

# ─────────────────────────────────────────────────────────────────────────────
# cargo · lint
# ─────────────────────────────────────────────────────────────────────────────

# Format all Rust source files in place (requires nightly).
# Example:  just cargo-fmt
[group('cargo · lint')]
cargo-fmt:
    cargo +nightly fmt --all

# Check formatting without modifying files — CI-safe (requires nightly).
# Example:  just cargo-fmt-check
[group('cargo · lint')]
cargo-fmt-check:
    cargo +nightly fmt --all --check

# Run clippy across the workspace with all features, treating warnings as errors.
# Example:  just cargo-clippy
[group('cargo · lint')]
cargo-clippy *args='':
    RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features {{ args }}

# Run formatting check then clippy — full lint gate.
# Example:  just cargo-lint
[group('cargo · lint')]
cargo-lint: cargo-fmt-check cargo-clippy

# ─────────────────────────────────────────────────────────────────────────────
# cargo · run
# ─────────────────────────────────────────────────────────────────────────────

# Run the World ID gateway service.
# Example:  just gateway
#           just gateway -- --help
[group('cargo · run')]
gateway *args='':
    cargo run -p world-id-gateway -- {{ args }}

# Run the World ID indexer service.
# Example:  just indexer
#           just indexer -- --help
[group('cargo · run')]
indexer *args='':
    cargo run -p world-id-indexer -- {{ args }}

# Run the OPRF node service.
# Example:  just oprf-node
#           just oprf-node -- --help
[group('cargo · run')]
oprf-node *args='':
    cargo run -p world-id-oprf-node -- {{ args }}

# Run the OPRF dev client (local development only).
# Example:  just dev-client
#           just dev-client -- --help
[group('cargo · run')]
dev-client *args='':
    cargo run -p world-id-oprf-dev-client -- {{ args }}

# Run the faux issuer (mock service for local testing).
# Example:  just faux-issuer
[group('cargo · run')]
faux-issuer *args='':
    cargo run -p world-id-faux-issuer -- {{ args }}

# ─────────────────────────────────────────────────────────────────────────────
# cargo · tools
# ─────────────────────────────────────────────────────────────────────────────

# Generate Solidity test fixtures from the Rust workspace.
# Example:  just generate-fixtures
[group('cargo · tools')]
generate-fixtures *args='':
    cargo run -p generate-solidity-fixtures -- {{ args }}
