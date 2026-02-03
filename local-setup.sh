#!/bin/bash

killall -9 anvil
killall -9 world-id-indexer
killall -9 world-id-gateway

# Clean up stale cache and database from previous runs
# echo "Cleaning up stale cache files..."
# rm -f /tmp/tree.mmap /tmp/tree.mmap.meta

# Clean up logs from previous runs
# echo "Clean up logs..."
# rm -f /tmp/forge-output.log /tmp/world-id-indexer.log /tmp/world-id-gateway.log

# echo "Cleaning up stale database tables..."
# PGPASSWORD=postgres psql -h localhost -U postgres -d world_id_indexer -c "TRUNCATE accounts, world_id_events RESTART IDENTITY CASCADE;" 2>/dev/null || true

anvil &
sleep 1
cd contracts
TREE_DEPTH=30 forge script script/WorldIDRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 2>&1 | tee /tmp/forge-output.log
cd ..

# Load environment variables from indexer .env
set -a
source services/indexer/.env
set +a

# Override with deployed registry address only if deployment succeeded
DEPLOYED_REGISTRY=$(grep "WorldIDRegistry deployed to:" /tmp/forge-output.log | tail -1 | awk '{print $4}')
if [ -n "$DEPLOYED_REGISTRY" ]; then
  export REGISTRY_ADDRESS="$DEPLOYED_REGISTRY"
fi
export TREE_CACHE_FILE="/tmp/tree.mmap"

cargo run --release -p world-id-indexer -- --http --indexer > /tmp/world-id-indexer.log 2>&1 &
until curl -sSf http://localhost:8080 2>&1 | grep -vq "Failed to connect"; do
  echo "Waiting for world-id-indexer HTTP server on localhost:8080..."
  sleep 1
done

# Start gateway with deployed registry address
cargo run --release -p world-id-gateway -- \
  --registry-addr "$DEPLOYED_REGISTRY" \
  --rpc-url http://localhost:8545 \
  --wallet-private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 > /tmp/world-id-gateway.log 2>&1 &
