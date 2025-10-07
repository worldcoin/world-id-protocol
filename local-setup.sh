!/bin/bash

killall -9 anvil
killall -9 authtree-indexer

anvil & 
sleep 1
cd contracts
forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ACCOUNT_REGISTRY=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 forge script script/CreateAccount.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
cd ..
REGISTRY_ADDRESS=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 cargo run --release -p authtree-indexer > /tmp/authtree-indexer.log 2>&1 &
until curl -sSf http://localhost:8080 2>&1 | grep -vq "Failed to connect"; do
  echo "Waiting for authtree-indexer HTTP server on localhost:8080..."
  sleep 1
done
cargo run -p world-id-core --bin issuer --features cli -- 0 > /tmp/credential.json
cargo run -p world-id-core --bin rp --features cli -- 123 > /tmp/rp_request.json
RUST_LOG=debug SEED=0101010101010101010101010101010101010101010101010101010101010101 cargo run -p world-id-core --features "authenticator cli" --bin authenticator /tmp/credential.json /tmp/rp_request.json