!/bin/bash

killall -9 anvil
killall -9 world-id-indexer
killall -9 world-id-gateway

anvil &
sleep 1
cd contracts
TREE_DEPTH=30 forge script script/WorldIDRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
cd ..
cargo run --release -p world-id-indexer -- --http --indexer > /tmp/world-id-indexer.log 2>&1 &
until curl -sSf http://localhost:8080 2>&1 | grep -vq "Failed to connect"; do
  echo "Waiting for world-id-indexer HTTP server on localhost:8080..."
  sleep 1
done
# FIXME: use .env file
REGISTRY_ADDRESS=0xc9A0165FA64fD336035C7D9183C211034E8021B3 WALLET_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 cargo run --release -p world-id-gateway &
