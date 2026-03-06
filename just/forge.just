# Solidity build, formatting, and quality recipes.
# Uses CONTRACTS_DIR from the root Justfile.

# Build all contracts
[group('build')]
build:
    cd {{ CONTRACTS_DIR }} && forge build --silent

# Format Solidity source files in place
[group('build')]
fmt:
    cd {{ CONTRACTS_DIR }} && forge fmt

# Check formatting without modifying files (CI-safe)
[group('build')]
fmt-check:
    cd {{ CONTRACTS_DIR }} && forge fmt --check

# Remove compiled artifacts and cache
[group('build')]
clean:
    cd {{ CONTRACTS_DIR }} && forge clean

# Save a gas baseline snapshot to .gas-snapshot
[group('build')]
snapshot:
    cd {{ CONTRACTS_DIR }} && forge snapshot

# Compare gas usage against the saved snapshot (fails on regression)
[group('build')]
snapshot-check:
    cd {{ CONTRACTS_DIR }} && forge snapshot --check

# Generate an LCOV coverage report
[group('build')]
coverage:
    cd {{ CONTRACTS_DIR }} && forge coverage --via-ir

# Print a gas report for all tests
[group('build')]
gas:
    cd {{ CONTRACTS_DIR }} && forge test --gas-report
