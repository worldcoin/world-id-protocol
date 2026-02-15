#!/bin/bash
# E2E Setup Script
#
# Deploys WorldChainBridge + mock registries to a local anvil instance,
# calls propagateState, then fetches real MPT proofs and commitment data.
# Outputs a JSON fixture file for the E2E relay test.
#
# Usage:  ./test/scripts/e2e_setup.sh [anvil_port] [output_file]
# Requires: anvil, cast, jq, curl

set -euo pipefail

ANVIL_PORT="${1:-18545}"
OUTPUT_FILE="${2:-test/fixtures/e2e_data.json}"
RPC="http://127.0.0.1:$ANVIL_PORT"
PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil default key[0]
SENDER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# ── Test values ──
ROOT=123456789
ISSUER_ID=90       # 0x5a
ISSUER_X=1111
ISSUER_Y=2222
OPRF_ID=171        # 0xAB
OPRF_X=3333
OPRF_Y=4444

# ── Cleanup ──
cleanup() { kill "$ANVIL_PID" 2>/dev/null || true; }
trap cleanup EXIT

# ── Start anvil ──
echo "[e2e] Starting anvil on port $ANVIL_PORT (chain-id 480)..."
anvil --port "$ANVIL_PORT" --chain-id 480 --silent &
ANVIL_PID=$!
sleep 2

# Verify anvil is running
if ! cast chain-id --rpc-url "$RPC" > /dev/null 2>&1; then
    echo "[e2e] ERROR: anvil failed to start" >&2
    exit 1
fi

# ── Helper: deploy contract from forge artifacts ──
deploy() {
    local artifact_path="$1"
    local constructor_args="${2:-}"
    local bytecode
    bytecode=$(jq -r '.bytecode.object' "$artifact_path")

    local deploy_data="$bytecode"
    if [ -n "$constructor_args" ]; then
        deploy_data="${bytecode}${constructor_args#0x}"
    fi

    local result
    result=$(cast send --rpc-url "$RPC" --private-key "$PK" --json --create "$deploy_data")
    echo "$result" | jq -r '.contractAddress'
}

# ── Deploy mock registries ──
echo "[e2e] Deploying mock registries..."
REGISTRY=$(deploy "out/E2EMocks.sol/MockWorldIDRegistryE2E.json")
ISSUER_REG=$(deploy "out/E2EMocks.sol/MockIssuerRegistryE2E.json")
OPRF_REG=$(deploy "out/E2EMocks.sol/MockOprfRegistryE2E.json")
echo "  Registry:       $REGISTRY"
echo "  IssuerRegistry: $ISSUER_REG"
echo "  OprfRegistry:   $OPRF_REG"

# ── Set mock state ──
echo "[e2e] Setting mock state (root=$ROOT, issuer=$ISSUER_ID, oprf=$OPRF_ID)..."
cast send "$REGISTRY" "setRoot(uint256)" "$ROOT" \
    --rpc-url "$RPC" --private-key "$PK" > /dev/null
cast send "$ISSUER_REG" "setPubkey(uint64,uint256,uint256)" "$ISSUER_ID" "$ISSUER_X" "$ISSUER_Y" \
    --rpc-url "$RPC" --private-key "$PK" > /dev/null
cast send "$OPRF_REG" "setKey(uint160,uint256,uint256)" "$OPRF_ID" "$OPRF_X" "$OPRF_Y" \
    --rpc-url "$RPC" --private-key "$PK" > /dev/null

# ── Deploy WorldChainBridge ──
echo "[e2e] Deploying WorldChainBridge..."
WC_ARGS=$(cast abi-encode "constructor(address,address,address)" "$REGISTRY" "$ISSUER_REG" "$OPRF_REG")
WC_IMPL=$(deploy "out/WorldChainBridge.sol/WorldChainBridge.json" "$WC_ARGS")
echo "  Impl: $WC_IMPL"

# Deploy proxy
INIT_CALLDATA=$(cast calldata "initialize(string,string,address,address)" "WorldChain" "1" "$SENDER" "0x0000000000000000000000000000000000000000")
PROXY_ARGS=$(cast abi-encode "constructor(address,bytes)" "$WC_IMPL" "$INIT_CALLDATA")
WC_BRIDGE=$(deploy "out/ERC1967Proxy.sol/ERC1967Proxy.json" "$PROXY_ARGS")
echo "  Proxy: $WC_BRIDGE"

# ── Call propagateState ──
echo "[e2e] Calling propagateState..."
cast send "$WC_BRIDGE" "propagateState(uint64[],uint160[])" "[$ISSUER_ID]" "[$OPRF_ID]" \
    --rpc-url "$RPC" --private-key "$PK" > /dev/null

# ── Mine an extra block to finalize ──
cast rpc anvil_mine '"0x1"' --rpc-url "$RPC" > /dev/null

# ── Read block data ──
# propagateState was in (latest - 1) since we mined an extra block
LATEST_BLOCK=$(cast block-number --rpc-url "$RPC")
PROP_BLOCK=$((LATEST_BLOCK - 1))
PROP_BLOCK_HEX=$(printf "0x%x" "$PROP_BLOCK")

echo "[e2e] Fetching block $PROP_BLOCK data..."
BLOCK_JSON=$(cast block "$PROP_BLOCK" --rpc-url "$RPC" --json)
STATE_ROOT=$(echo "$BLOCK_JSON" | jq -r '.stateRoot')
echo "  StateRoot: $STATE_ROOT"

# ── Read chain head from ERC-7201 storage slot ──
# keccak256(abi.encode(uint256(keccak256("worldid.storage.WorldIDStateBridge")) - 1)) & ~bytes32(uint256(0xff))
CHAIN_HEAD_SLOT="0x8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00"
CHAIN_HEAD=$(cast storage "$WC_BRIDGE" "$CHAIN_HEAD_SLOT" --rpc-url "$RPC" --block "$PROP_BLOCK")
echo "  ChainHead: $CHAIN_HEAD"

# ── Read latest root ──
LATEST_ROOT_RAW=$(cast call "$WC_BRIDGE" "latestRoot()(uint256)" --rpc-url "$RPC" --block "$PROP_BLOCK")
# Strip cast formatting (e.g., "123456789 [1.234e8]" → "123456789")
LATEST_ROOT=$(echo "$LATEST_ROOT_RAW" | awk '{print $1}')
echo "  LatestRoot: $LATEST_ROOT"

# ── Fetch MPT proofs ──
echo "[e2e] Fetching MPT proofs via eth_getProof..."
SLOT_KEY="$CHAIN_HEAD_SLOT"
PROOF_JSON=$(curl -s -X POST "$RPC" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getProof\",\"params\":[\"$WC_BRIDGE\",[\"$SLOT_KEY\"],\"$PROP_BLOCK_HEX\"],\"id\":1}")

ACCOUNT_PROOF=$(echo "$PROOF_JSON" | jq -c '.result.accountProof')
STORAGE_PROOF=$(echo "$PROOF_JSON" | jq -c '.result.storageProof[0].proof')
PROVEN_VALUE=$(echo "$PROOF_JSON" | jq -r '.result.storageProof[0].value')
ACCT_PROOF_LEN=$(echo "$PROOF_JSON" | jq '.result.accountProof | length')
STOR_PROOF_LEN=$(echo "$PROOF_JSON" | jq '.result.storageProof[0].proof | length')
echo "  AccountProof nodes: $ACCT_PROOF_LEN"
echo "  StorageProof nodes: $STOR_PROOF_LEN"
echo "  Proven slot 0 value: $PROVEN_VALUE"

# ── Fetch commitment payload from ChainCommitted event ──
echo "[e2e] Fetching ChainCommitted event..."
LOGS_JSON=$(cast logs --from-block "$PROP_BLOCK" --to-block "$PROP_BLOCK" \
    --address "$WC_BRIDGE" --rpc-url "$RPC" --json \
    "ChainCommitted(bytes32,uint256,bytes)")

EVENT_DATA=$(echo "$LOGS_JSON" | jq -r '.[0].data')
# Event data = abi.encode(bytes commitPayload) where commitPayload = abi.encode(Commitment[])
# We use cast to decode the outer bytes wrapper
COMMIT_PAYLOAD=$(cast abi-decode --input "f(bytes)" "$EVENT_DATA" | head -1)
echo "  CommitPayload length: ${#COMMIT_PAYLOAD}"

# ── Write JSON fixture ──
echo "[e2e] Writing fixture to $OUTPUT_FILE..."
mkdir -p "$(dirname "$OUTPUT_FILE")"
cat > "$OUTPUT_FILE" << JSONEOF
{
  "stateRoot": "$STATE_ROOT",
  "wcBridge": "$WC_BRIDGE",
  "chainHead": "$CHAIN_HEAD",
  "latestRoot": "$LATEST_ROOT",
  "commitPayload": "$COMMIT_PAYLOAD",
  "accountProof": $ACCOUNT_PROOF,
  "storageProof": $STORAGE_PROOF
}
JSONEOF

echo "[e2e] Done. Fixture written to $OUTPUT_FILE"
