
_SCRIPTS_CORE_DIR := CONTRACTS_DIR / "script/core"
_SCRIPTS_CROSSCHAIN_DIR := CONTRACTS_DIR / "script/crosschain"

_DEPLOYER := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
_RELAYER  := "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
_SIGNER   := "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

# Deploy core contracts (WorldIDRegistry, Issuers, RpRegistry, Verifier) to WC.
[group('deploy')]
deploy-core:
    cd {{ CONTRACTS_DIR }} && forge script script/core/Deploy.s.sol:Deploy \
        --sig "run(string)" "local" \
        --rpc-url {{ WC_RPC }} --broadcast --private-key {{ _DEPLOYER }} \
        --skip-simulation --slow

# Deploy bridge contracts across WC + destinations (multi-chain).
# RPCs are read from crosschain/config/local.json — run `just inject-rpcs` first.
[group('deploy')]
deploy-bridge:
    cd {{ CONTRACTS_DIR }} && PRIVATE_KEY={{ _DEPLOYER }} forge script \
        script/crosschain/Deploy.s.sol:Deploy \
        --sig "run(string)" "local" --multi --broadcast \
        --skip-simulation --slow

# Write WC_RPC and ETH_RPC into the crosschain local config.
[group('deploy')]
inject-rpcs:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg="{{ CONTRACTS_DIR }}/script/crosschain/config/local.json"
    jq --arg wc "{{ WC_RPC }}" --arg eth "{{ ETH_RPC }}" \
        '.worldchain.rpc = $wc | .ethereum.rpc = $eth' "$cfg" > "$cfg.tmp" && mv "$cfg.tmp" "$cfg"

# Full local deployment: core + bridge.
[group('deploy')]
deploy-local:
    just deploy-core
    just inject-rpcs
    just deploy-bridge

# Generate + run the registry bootstrap script against a local anvil.
[group('test')]
bootstrap *XTASK_ARGS:
    cargo run -p xtask -- gen-alloc {{ XTASK_ARGS }}
    cd {{ CONTRACTS_DIR }} && forge script script/crosschain/Bootstrap.s.sol:BootstrapRegistries \
        --rpc-url {{ WC_RPC }} --broadcast --private-key {{ _DEPLOYER }} --skip-simulation --slow

# Generate the bootstrap script only (no deploy).
[group('test')]
gen-alloc *ARGS:
    cargo run -p xtask -- gen-alloc {{ ARGS }}
