# E2E testing recipes.
# Genesis allocs follow the OP bedrock predeploy pattern (vm.etch + vm.store + vm.dumpState).

_E2E_FIXTURES := CONTRACTS_DIR / "test/crosschain/fixtures/e2e_relay"

# Generate WC + ETH genesis allocs (no RPC needed).
[group('e2e')]
gen-allocs:
    cd {{ CONTRACTS_DIR }} && forge script script/crosschain/E2E_Bootstrap.s.sol:GenAllocsWc
    cd {{ CONTRACTS_DIR }} && forge script script/crosschain/E2E_Bootstrap.s.sol:GenAllocsEth
