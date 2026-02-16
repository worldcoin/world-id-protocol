# Common broadcast flags for forge scripts.
_BROADCAST_FLAGS := "--broadcast --private-key " + PRIVATE_KEY

# Run all tests (core, bridge, e2e in parallel)
[group('test')]
test *args='': test-bridge test-world-id it-all

[group('test')]
test-bridge:
    cd {{ BRIDGE_DIR }} && forge test

[group('test')]
test-world-id:
    cd {{ CONTRACTS_DIR }} && forge test

 
# Gas report
[group('test')]
gas:
    cd {{ BRIDGE_DIR }} && forge test --gas-report
    cd {{ CONTRACTS_DIR }} && forge test --gas-report

# Gas snapshot (save baseline, diff on re-run)
[group('test')]
snapshot:
    cd {{ BRIDGE_DIR }} && forge snapshot
    cd {{ CONTRACTS_DIR }} && forge snapshot

# Code coverage
[group('test')]
coverage:
    cd {{ BRIDGE_DIR }} && forge coverage -- --via--ir
    # cd {{ CONTRACTS_DIR }} && forge coverage -- --via--ir

# Format Solidity source
[group('test')]
fmt:
    cd {{ CONTRACTS_DIR }} && forge fmt
    cd {{ BRIDGE_DIR }} && forge fmt


# Run a broadcast forge script against bridge contracts
[private]
_bridge-script script rpc *args='':
    cd {{ BRIDGE_DIR }} && forge script {{ script }} --rpc-url {{ rpc }} {{ _BROADCAST_FLAGS }} {{ args }}

