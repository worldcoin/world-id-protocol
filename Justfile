# ──────────────────────────────────────────────────────────────────────────────
# World ID Protocol — Root Justfile
#
# Forwards to subdirectory Justfiles.
# ──────────────────────────────────────────────────────────────────────────────

set dotenv-load := true
set positional-arguments

bridge_dir := "bridge/contracts"

# Install dependencies (git submodules)
install:
    git submodule update --init --recursive

# ── Bridge ────────────────────────────────────────────────────────────────────

# Deploy all bridge contracts
deploy-all *args='':
    just --justfile {{ bridge_dir }}/Justfile deploy-all {{ args }}

# Deploy a single destination chain
deploy-chain *args='':
    just --justfile {{ bridge_dir }}/Justfile deploy-chain {{ args }}

# Dry-run bridge deployment
dry-run *args='':
    just --justfile {{ bridge_dir }}/Justfile dry-run {{ args }}

# Show bridge deployment status
status *args='':
    just --justfile {{ bridge_dir }}/Justfile status {{ args }}

# Verify bridge contracts on block explorer
verify *args='':
    just --justfile {{ bridge_dir }}/Justfile verify {{ args }}

# Authorize a gateway on a satellite
authorize-gateway *args='':
    just --justfile {{ bridge_dir }}/Justfile authorize-gateway {{ args }}

# Revoke a gateway from a satellite
revoke-gateway *args='':
    just --justfile {{ bridge_dir }}/Justfile revoke-gateway {{ args }}

# Transfer ownership of a bridge contract
transfer-ownership *args='':
    just --justfile {{ bridge_dir }}/Justfile transfer-ownership {{ args }}

# Print resolved bridge env vars
print-env *args='':
    just --justfile {{ bridge_dir }}/Justfile print-env {{ args }}

# Build bridge contracts
build:
    just --justfile {{ bridge_dir }}/Justfile build

# Run bridge tests
test *args='':
    just --justfile {{ bridge_dir }}/Justfile test {{ args }}

# Format bridge contracts
fmt:
    just --justfile {{ bridge_dir }}/Justfile fmt

# Check bridge formatting
fmt-check:
    just --justfile {{ bridge_dir }}/Justfile fmt-check

# Full bridge CI check
check:
    just --justfile {{ bridge_dir }}/Justfile check

# Clean bridge build artifacts
clean:
    just --justfile {{ bridge_dir }}/Justfile clean
