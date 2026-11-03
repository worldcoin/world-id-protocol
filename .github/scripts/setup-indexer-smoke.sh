#!/usr/bin/env bash
set -euo pipefail

rpc_url="http://127.0.0.1:${INDEXER_SMOKE_RPC_PORT:-8545}"
anvil --host 127.0.0.1 --port "${INDEXER_SMOKE_RPC_PORT:-8545}" > "$RUNNER_TEMP/indexer-smoke-anvil.log" 2>&1 &
echo "$!" > "$RUNNER_TEMP/indexer-smoke-anvil.pid"

for attempt in {1..30}; do
    if cast block-number --rpc-url "$rpc_url" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done
sender=$(cast rpc --rpc-url "$rpc_url" eth_accounts | jq -er '.[0]')

deploy() {
    local bytecode
    bytecode=$(jq -er '.bytecode.object' "$1")
    cast send --rpc-url "$rpc_url" --unlocked --from "$sender" --json \
        --create "${bytecode}${2:-}" | jq -er '.contractAddress'
}

# Reuse the verifier tests' registry fixture; this smoke test only exercises startup/health.
registry=$(deploy contracts/out/WorldIDVerifierTest.t.sol/WorldIDRegistryMock.json)
groth16=$(deploy contracts/out/Verifier.sol/Verifier.json)
implementation=$(deploy contracts/out/WorldIDVerifierV2.sol/WorldIDVerifierV2.json)
# Issuer and OPRF reads are unused by the health check. Proof verification has separate tests.
initialization=$(cast calldata 'initialize(address,address,address,address,uint64)' \
    "$registry" "$registry" "$registry" "$groth16" 3600)
constructor=$(cast abi-encode 'constructor(address,bytes)' "$implementation" "$initialization")
verifier=$(deploy contracts/out/ERC1967Proxy.sol/ERC1967Proxy.json "${constructor#0x}")

{
    echo "RPC_URL=$rpc_url"
    echo "REGISTRY_ADDRESS=$registry"
    echo "VERIFIER_ADDRESS=$verifier"
    echo "TREE_DEPTH=30"
} >> "$GITHUB_ENV"
