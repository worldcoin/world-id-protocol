[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

run-nodes:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build -p world-id-oprf-node --release
    # anvil wallet 7
    RUST_LOG="taceo_oprf_service=trace,world_id_oprf_node=trace,warn" ./target/release/world-id-oprf-node --bind-addr 127.0.0.1:10000 --rp-secret-id-prefix oprf/rp/n0 --environment dev --wallet-address 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955 --version-req ">=0.2.0" > logs/node0.log 2>&1 &
    pid0=$!
    echo "started node0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="taceo_oprf_service=trace,world_id_oprf_node=trace,warn" ./target/release/world-id-oprf-node --bind-addr 127.0.0.1:10001 --rp-secret-id-prefix oprf/rp/n1 --environment dev --wallet-address 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f --version-req ">=0.2.0" > logs/node1.log 2>&1 &
    pid1=$!
    echo "started node1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="taceo_oprf_service=trace,world_id_oprf_node=trace,warn" ./target/release/world-id-oprf-node --bind-addr 127.0.0.1:10002 --rp-secret-id-prefix oprf/rp/n2 --environment dev --wallet-address 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 --version-req ">=0.2.0" > logs/node2.log 2>&1  &
    pid2=$!
    echo "started node2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

run-setup:
    #!/usr/bin/env bash
    killall -9 anvil
    killall -9 world-id-oprf-node
    anvil &
    sleep 1
    mkdir -p logs
    echo "starting localstack and anvil"
    docker compose up -d localstack postgres
    sleep 1
    echo "preparing localstack"
    just prepare-localstack-secrets
    echo "starting WorldIDRegistry contract..."
    just deploy-world-id-registry-anvil | tee logs/deploy_world_id_registry.log
    world_id_registry=$(grep -oP 'WorldIDRegistry deployed to: \K0x[a-fA-F0-9]+' logs/deploy_world_id_registry.log)
    echo "starting OprfKeyRegistry contract.."
    just deploy-oprf-key-registry-with-deps-anvil | tee logs/deploy_oprf_key_registry.log
    oprf_key_registry=$(grep -oP 'OprfKeyRegistry deployed to: \K0x[a-fA-F0-9]+' logs/deploy_oprf_key_registry.log)
    echo "register oprf-nodes..."
    OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry just register-participants-anvil
    echo "starting indexer..."
    REGISTRY_ADDRESS=$world_id_registry just run-indexer-and-gateway
    echo "starting OPRF key-gen instances..."
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry docker compose up -d oprf-key-gen0 oprf-key-gen1 oprf-key-gen2
    echo "starting OPRF nodes..."
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry OPRF_NODE_WORLD_ID_REGISTRY_CONTRACT=$world_id_registry just run-nodes
    echo "stopping containers..."
    docker compose down
    killall -9 world-id-indexer
    killall -9 world-id-indexer
    killall -9 world-id-oprf-node
    killall -9 anvil

run-oprf-key-registry-and-nodes $OPRF_SERVICE_WORLD_ID_REGISTRY_CONTRACT:
    #!/usr/bin/env bash
    mkdir -p logs
    echo "starting OprfKeyRegistry contract.."
    just deploy-oprf-key-registry-with-deps-anvil | tee logs/deploy_oprf_key_registry.log
    oprf_key_registry=$(grep -oP 'OprfKeyRegistry deployed to: \K0x[a-fA-F0-9]+' logs/deploy_oprf_key_registry.log)
    sleep 1
    echo "starting OPRF services..."
    OPRF_SERVICE_RP_REGISTRY_CONTRACT=$oprf_key_registry just run-nodes

run-dev-client *args:
    cargo build -p world-id-oprf-dev-client --release
    ./target/release/world-id-oprf-dev-client {{ args }}

[private]
run-indexer-and-gateway:
    #!/usr/bin/env bash
    killall -9 world-id-indexer
    killall -9 world-id-gateway
    mkdir -p logs
    RPC_URL=http://localhost:8545 WS_URL=ws://localhost:8545 DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo run --release -p world-id-indexer -- --http --indexer > logs/world-id-indexer.log 2>&1 &
    indexer_pid=$!
    echo "started indexer with PID $indexer_pid"
    until curl -sSf http://localhost:8080 2>&1 | grep -vq "Failed to connect"; do
        echo "Waiting for world-id-indexer HTTP server on localhost:8080..."
        sleep 1
    done
    RPC_URL=http://localhost:8545 WS_URL=ws://localhost:8545 DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres WALLET_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 cargo run --release -p world-id-gateway > logs/world-id-gateway.log 2>&1 &
    gateway_pid=$!
    echo "started gateway with PID $gateway_pid"

[private]
[working-directory('contracts/script')]
deploy-world-id-registry-anvil:
    forge script WorldIDRegistry.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[private]
[working-directory('contracts/lib/oprf-key-registry/script/deploy')]
deploy-oprf-key-registry-with-deps-anvil:
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script OprfKeyRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[private]
[working-directory('contracts/lib/oprf-key-registry/script')]
register-participants-anvil:
    PARTICIPANT_ADDRESSES=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[private]
prepare-localstack-secrets:
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n0 \
      --secret-string '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356'
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n1 \
      --secret-string '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97'
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n2 \
      --secret-string '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6'
