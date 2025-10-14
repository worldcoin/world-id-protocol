!/bin/bash

killall -9 anvil
killall -9 authtree-indexer
killall -9 registry-gateway

anvil &
sleep 1
cd contracts
TREE_DEPTH=30 forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
cd ..
cargo run --release -p authtree-indexer -- --http --indexer > /tmp/authtree-indexer.log 2>&1 &
until curl -sSf http://localhost:8000 2>&1 | grep -vq "Failed to connect"; do
  echo "Waiting for authtree-indexer HTTP server on localhost:8000..."
  sleep 1
done
# FIXME: use .env file
REGISTRY_ADDRESS=0xd66aFbf92d684B4404B1ed3e9aDA85353c178dE2 WALLET_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 cargo run --release -p registry-gateway &
