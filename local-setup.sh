!/bin/bash

killall -9 anvil
killall -9 authtree-indexer
killall -9 registry-gateway

anvil &
sleep 1
cd contracts
TREE_DEPTH=30 forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
cd ..
REGISTRY_ADDRESS=0x3ae6291e4359887C9C35230184C05e3F7DDe7020 cargo run --release -p authtree-indexer -- --http --indexer > /tmp/authtree-indexer.log 2>&1 &
until curl -sSf http://localhost:8080 2>&1 | grep -vq "Failed to connect"; do
  echo "Waiting for authtree-indexer HTTP server on localhost:8080..."
  sleep 1
done
REGISTRY_ADDRESS=0x3ae6291e4359887C9C35230184C05e3F7DDe7020 WALLET_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 cargo run --release -p registry-gateway &
