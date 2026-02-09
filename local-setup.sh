#!/usr/bin/env bash

# Clean up stale cache from previous runs
# echo "Cleaning up stale cache files..."
# rm -f /tmp/tree.mmap /tmp/tree.mmap.meta

set -eu

NOCOLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'

PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

create_secret() {
    local name="$1"
    local value="$2"
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws \
        --region us-east-1 \
        --endpoint-url http://localhost:4566 \
        secretsmanager create-secret \
        --name "$name" \
        --secret-string "$value"
}

wait_for_health() {
    local port=$1
    local name=$2
    local timeout=${3:-60}
    local start_time=$(date +%s)
    echo "waiting for $name on port $port to be healthy..."

    while true; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/health" || echo "000")
        if [[ "$http_code" == "200" ]]; then
            echo "$name is healthy!"
            break
        fi
        now=$(date +%s)
        if (( now - start_time >= timeout )); then
            echo -e "${RED}error: $name did not become healthy after $timeout seconds${NOCOLOR}" >&2
            exit 1
        fi
        sleep 1
    done
}

deploy_contracts() {
    # deploy ERC20Mock as fee token
    (cd contracts && forge script script/ERC20Mock.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    erc20_mock=$(jq -r '.transactions[] | select(.contractName == "ERC20Mock") | .contractAddress' ./contracts/broadcast/ERC20Mock.s.sol/31337/run-latest.json)
    echo "ERC20Mock: $erc20_mock"

    # deploy OprfKeyRegistry for 3 nodes and register anvil wallets 7,8,9 as participants
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script lib/oprf-key-registry/script/deploy/OprfKeyRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    oprf_key_registry=$(jq -r '.transactions[] | select(.contractName == "ERC1967Proxy") | .contractAddress' ./contracts/broadcast/OprfKeyRegistryWithDeps.s.sol/31337/run-latest.json)
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry PARTICIPANT_ADDRESSES=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script lib/oprf-key-registry/script/RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    echo "OprfKeyRegistry: $oprf_key_registry"

    # deploy all other contracts
    (cd contracts && forge script script/Deploy.s.sol --sig "run(string)" "local" --broadcast --rpc-url http://localhost:8545 --private-key $PK)
    world_id_registry=$(jq -r ".worldIDRegistry.proxy" ./contracts/deployments/local.json)
    echo "WorldIDRegistry: $world_id_registry"
    rp_registry=$(jq -r ".rpRegistry.proxy" ./contracts/deployments/local.json)
    echo "RpRegistry: $rp_registry"
    credential_schema_issuer_registry=$(jq -r ".credentialSchemaIssuerRegistry.proxy" ./contracts/deployments/local.json)
    echo "CredentialSchemaIssuerRegistry: $credential_schema_issuer_registry"

    # register RpRegistry and CredentialSchemaIssuerRegistry as OPRF key-gen admins
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry ADMIN_ADDRESS_REGISTER=$rp_registry forge script lib/oprf-key-registry/script/RegisterKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry ADMIN_ADDRESS_REGISTER=$credential_schema_issuer_registry forge script lib/oprf-key-registry/script/RegisterKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
}

start_node() {
    local i="$1"
    local port=$((10000 + i))
    local db_port=$((5440 + i))
    local db_conn="postgres://postgres:postgres@localhost:$db_port/postgres"
    RUST_LOG="taceo_oprf_service=trace,world_id_oprf_node=trace,warn" \
    ./target/release/world-id-oprf-node \
        --bind-addr 127.0.0.1:$port \
        --environment dev \
        --version-req ">=0.0.0" \
        --oprf-key-registry-contract $oprf_key_registry \
        --world-id-registry-contract $world_id_registry \
        --rp-registry-contract $rp_registry \
        --credential-schema-issuer-registry-contract $credential_schema_issuer_registry \
        --db-connection-string $db_conn \
        --db-schema oprf \
        > logs/node$i.log 2>&1 &
    pid=$!
    echo "started world-id-oprf-node $i with PID $pid"
}

run_indexer_and_gateway() {
    REGISTRY_ADDRESS=$world_id_registry RPC_URL=http://localhost:8545 WS_URL=ws://localhost:8545 DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres TREE_CACHE_FILE=/tmp/tree.mmap cargo run --release -p world-id-indexer -- --http --indexer > logs/world-id-indexer.log 2>&1 &
    indexer_pid=$!
    echo "started indexer with PID $indexer_pid"
    wait_for_health 8080 "world-id-indexer" 300

    REGISTRY_ADDRESS=$world_id_registry RPC_URL=http://localhost:8545 WALLET_PRIVATE_KEY=$PK cargo run --release -p world-id-gateway > logs/world-id-gateway.log 2>&1 &
    gateway_pid=$!
    echo "started gateway with PID $gateway_pid"
    wait_for_health 8081 "world-id-gateway" 300
}

teardown() {
    docker compose down
    killall -9 world-id-oprf-node 2>/dev/null || true
    killall -9 world-id-indexer 2>/dev/null || true
    killall -9 world-id-gateway 2>/dev/null || true
    killall -9 anvil 2>/dev/null || true
}

setup() {
    rm -rf logs
    mkdir -p logs
    teardown
    trap teardown EXIT SIGINT SIGTERM

    anvil &

    docker compose up -d localstack postgres oprf-node-db0 oprf-node-db1 oprf-node-db2

    echo -e "${GREEN}deploying contracts..${NOCOLOR}"
    deploy_contracts

    echo -e "${GREEN}starting world-id-indexer and world-id-gateway..${NOCOLOR}"
    run_indexer_and_gateway

    echo -e "${GREEN}starting OPRF key-gen nodes..${NOCOLOR}"
    create_secret "oprf/eth/n0" "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"
    create_secret "oprf/eth/n1" "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"
    create_secret "oprf/eth/n2" "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry docker compose up -d oprf-key-gen0 oprf-key-gen1 oprf-key-gen2
    wait_for_health 20000 "oprf-key-gen0" 300
    wait_for_health 20001 "oprf-key-gen1" 300
    wait_for_health 20002 "oprf-key-gen2" 300

    echo -e "${GREEN}starting OPRF nodes..${NOCOLOR}"
    cargo build -p world-id-oprf-node --release
    start_node 0
    start_node 1
    start_node 2
    wait_for_health 10000 "world-id-oprf-node0" 300
    wait_for_health 10001 "world-id-oprf-node1" 300
    wait_for_health 10002 "world-id-oprf-node2" 300
}

client() {
    oprf_key_registry=$(jq -r '.transactions[] | select(.contractName == "ERC1967Proxy") | .contractAddress' ./contracts/broadcast/OprfKeyRegistryWithDeps.s.sol/31337/run-latest.json)
    world_id_registry=$(jq -r ".worldIDRegistry.proxy" ./contracts/deployments/local.json)
    rp_registry=$(jq -r ".rpRegistry.proxy" ./contracts/deployments/local.json)
    credential_schema_issuer_registry=$(jq -r ".credentialSchemaIssuerRegistry.proxy" ./contracts/deployments/local.json)
    # use addresses from deploy logs or use existing env vars
    OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=${OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT:-$oprf_key_registry} OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT=${OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT:-$world_id_registry} OPRF_DEV_CLIENT_RP_REGISTRY_CONTRACT=${OPRF_DEV_CLIENT_RP_REGISTRY_CONTRACT:-$rp_registry} OPRF_DEV_CLIENT_CREDENTIAL_SCHEMA_ISSUER_REGISTRY_CONTRACT=${OPRF_DEV_CLIENT_CREDENTIAL_SCHEMA_ISSUER_REGISTRY_CONTRACT:-$credential_schema_issuer_registry} cargo run --release --bin world-id-oprf-dev-client -- "$@"
}

main() {
    if [ $# -lt 1 ]; then
        echo "usage: $0 <command>"
        exit 1
    fi

    if [[ $1 = "setup" ]]; then
        echo -e "${GREEN}running setup..${NOCOLOR}"
        setup
        echo -e "${GREEN}press Ctrl+C to stop${NOCOLOR}"
        wait
    elif [[ $1 = "client" ]]; then
        echo -e "${GREEN}running client..${NOCOLOR}"
        client "${@:2}"
    elif [[ $1 = "test" ]]; then
        echo -e "${GREEN}running test..${NOCOLOR}"
        setup
        client test
    else
        echo "unknown command: '$1'"
        exit 1
    fi
}

main "$@"
