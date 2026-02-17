# Common broadcast flags for forge scripts.
_BROADCAST_FLAGS := "--broadcast --private-key " + PRIVATE_KEY

# Run all tests (core + bridge + e2e)
[group('test')]
test *args='': test-world-id test-bridge it-all

[group('test')]
test-bridge:
    cd {{ CONTRACTS_DIR }} && forge test --match-path 'test/crosschain/*'

[group('test')]
test-world-id:
    cd {{ CONTRACTS_DIR }} && forge test --no-match-path 'test/crosschain/*'

# Gas report
[group('test')]
gas:
    cd {{ CONTRACTS_DIR }} && forge test --gas-report

# Gas snapshot (save baseline, diff on re-run)
[group('test')]
snapshot:
    cd {{ CONTRACTS_DIR }} && forge snapshot

# Code coverage
[group('test')]
coverage:
    cd {{ CONTRACTS_DIR }} && forge coverage -- --via--ir

# Format Solidity source
[group('test')]
fmt:
    cd {{ CONTRACTS_DIR }} && forge fmt

[group('test')]
clean:
    cd {{ CONTRACTS_DIR }} && forge clean

# Run a broadcast forge script against bridge contracts
[private]
_bridge-script script rpc *args='':
    cd {{ CONTRACTS_DIR }} && forge script {{ script }} --rpc-url {{ rpc }} {{ _BROADCAST_FLAGS }} {{ args }}
