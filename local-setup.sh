#!/usr/bin/env bash

# Clean up stale cache from previous runs
# echo "Cleaning up stale cache files..."
# rm -f /tmp/tree.mmap /tmp/tree.mmap.meta

set -eu

NOCOLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'

PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

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
    (cd contracts && forge script script/core/ERC20Mock.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    erc20_mock=$(jq -r '.transactions[] | select(.contractName == "ERC20Mock") | .contractAddress' ./contracts/broadcast/ERC20Mock.s.sol/31337/run-latest.json)
    echo "ERC20Mock: $erc20_mock"

    # deploy OprfKeyRegistry for 3 nodes and register anvil wallets 7,8,9 as participants
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script lib/oprf-key-registry/script/deploy/OprfKeyRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    # this should stay constant unless the contract changes, is also hardcoded in contracts/script/config/local.json
    oprf_key_registry=$(jq -r '.transactions[] | select(.contractName == "ERC1967Proxy") | .contractAddress' ./contracts/broadcast/OprfKeyRegistryWithDeps.s.sol/31337/run-latest.json)
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry PARTICIPANT_ADDRESSES=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script lib/oprf-key-registry/script/RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    echo "OprfKeyRegistry: $oprf_key_registry"

    # deploy all other contracts
    (cd contracts && forge script script/core/Deploy.s.sol --tc Deploy --sig "run(string)" "local" --broadcast --rpc-url http://localhost:8545 --private-key $PK)
    world_id_registry=$(jq -r ".worldIDRegistry.proxy" ./contracts/deployments/core/local.json)
    echo "WorldIDRegistry: $world_id_registry"
    rp_registry=$(jq -r ".rpRegistry.proxy" ./contracts/deployments/core/local.json)
    echo "RpRegistry: $rp_registry"
    credential_schema_issuer_registry=$(jq -r ".credentialSchemaIssuerRegistry.proxy" ./contracts/deployments/core/local.json)
    echo "CredentialSchemaIssuerRegistry: $credential_schema_issuer_registry"

    # register RpRegistry and CredentialSchemaIssuerRegistry as OPRF key-gen admins
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry ADMIN_ADDRESS_REGISTER=$rp_registry forge script lib/oprf-key-registry/script/RegisterKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry ADMIN_ADDRESS_REGISTER=$credential_schema_issuer_registry forge script lib/oprf-key-registry/script/RegisterKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
}

deploy_wip101_contracts() {
    # deploy the WIP101 scripts for testing
    (cd contracts && forge script script/core/Wip101Mock.s.sol:DeployWIP101 --broadcast --rpc-url http://localhost:8545 --private-key $PK)

    wip101_correct=$(jq -r '.transactions[] | select(.contractName == "WIP101Correct") | .contractAddress' ./contracts/broadcast/Wip101Mock.s.sol/31337/run-latest.json)
    wip101_aux=$(jq -r '.transactions[] | select(.contractName == "WIP101CorrectWhenAuxData") | .contractAddress' ./contracts/broadcast/Wip101Mock.s.sol/31337/run-latest.json)

    # create two RPs with hardcoded ID to test WIP101
    cast send $rp_registry \
    "register(uint64,address,address,string)" \
    101 $wip101_correct $wip101_correct "wip correct" \
    --private-key $PK \
    --rpc-url http://127.0.0.1:8545

    cast send $rp_registry \
    "register(uint64,address,address,string)" \
    102 $wip101_aux $wip101_aux "wip with aux" \
    --private-key $PK \
    --rpc-url http://127.0.0.1:8545
}

start_node() {
    local i="$1"
    local port=$((10000 + i))
    local db_conn="postgres://postgres:postgres@localhost:5432/postgres"
    RUST_LOG="taceo=trace,world_id_oprf_node=trace,alloy_provider=debug,warn" \
    TACEO_OPRF_NODE__BIND_ADDR=127.0.0.1:$port \
    TACEO_OPRF_NODE__SERVICE__WORLD_ID_REGISTRY_CONTRACT=$world_id_registry \
    TACEO_OPRF_NODE__SERVICE__RP_REGISTRY_CONTRACT=$rp_registry \
    TACEO_OPRF_NODE__SERVICE__CREDENTIAL_SCHEMA_ISSUER_REGISTRY_CONTRACT=$credential_schema_issuer_registry \
    TACEO_OPRF_NODE__SERVICE__OPRF__ENVIRONMENT=dev \
    TACEO_OPRF_NODE__SERVICE__OPRF__OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry \
    TACEO_OPRF_NODE__SERVICE__OPRF__VERSION_REQ=">=0.0.0" \
    TACEO_OPRF_NODE__SERVICE__RPC__HTTP_URLS=http://127.0.0.1:8545 \
    TACEO_OPRF_NODE__SERVICE__RPC__WS_URL=ws://127.0.0.1:8545 \
    TACEO_OPRF_NODE__SERVICE__RPC__CHAIN_ID=31337 \
    TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING=$db_conn \
    TACEO_OPRF_NODE__POSTGRES__SCHEMA=oprf$i \
    ./target/release/world-id-oprf-node > logs/node$i.log 2>&1 &
    pid=$!
    echo "started world-id-oprf-node $i with PID $pid"
}

run_indexer_and_gateway() {
    REGISTRY_ADDRESS=$world_id_registry RPC_URL=http://localhost:8545 WS_URL=ws://localhost:8545 DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres TREE_CACHE_FILE=/tmp/tree.mmap cargo run --release -p world-id-indexer -- --http --indexer > logs/world-id-indexer.log 2>&1 &
    indexer_pid=$!
    echo "started indexer with PID $indexer_pid"
    wait_for_health 8080 "world-id-indexer" 300

    REGISTRY_ADDRESS=$world_id_registry RPC_URL=http://localhost:8545 WALLET_PRIVATE_KEY=$PK REDIS_URL=redis://localhost:6379 cargo run --release -p world-id-gateway > logs/world-id-gateway.log 2>&1 &
    gateway_pid=$!
    echo "started gateway with PID $gateway_pid"
    wait_for_health 8081 "world-id-gateway" 300
}

teardown() {
    docker compose down || true
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

    anvil > logs/anvil.log 2>&1 &

    docker compose up -d postgres redis

    echo -e "${GREEN}deploying contracts..${NOCOLOR}"
    deploy_contracts

    echo -e "${GREEN}starting world-id-indexer and world-id-gateway..${NOCOLOR}"
    run_indexer_and_gateway

    echo -e "${GREEN}starting OPRF key-gen nodes..${NOCOLOR}"
    TACEO_OPRF_KEY_GEN__SERVICE__OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry docker compose up -d oprf-key-gen0 oprf-key-gen1 oprf-key-gen2
    docker compose logs -f oprf-key-gen0 > logs/key-gen0.log 2>&1 &
    docker compose logs -f oprf-key-gen1 > logs/key-gen1.log 2>&1 &
    docker compose logs -f oprf-key-gen2 > logs/key-gen2.log 2>&1 &
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
    # Set env vars only if they are not already set
    if [ -z "${OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT+x}" ]; then
        export OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$(jq -r '.transactions[] | select(.contractName == "ERC1967Proxy") | .contractAddress' ./contracts/broadcast/OprfKeyRegistryWithDeps.s.sol/31337/run-latest.json)
    fi
    if [ -z "${OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT+x}" ]; then
        export OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT=$(jq -r ".worldIDRegistry.proxy" ./contracts/deployments/core/local.json)
    fi
    if [ -z "${OPRF_DEV_CLIENT_RP_REGISTRY_CONTRACT+x}" ]; then
        export OPRF_DEV_CLIENT_RP_REGISTRY_CONTRACT=$(jq -r ".rpRegistry.proxy" ./contracts/deployments/core/local.json)
    fi
    if [ -z "${OPRF_DEV_CLIENT_ISSUER_SCHEMA_REGISTRY_CONTRACT+x}" ]; then
        export OPRF_DEV_CLIENT_ISSUER_SCHEMA_REGISTRY_CONTRACT=$(jq -r ".credentialSchemaIssuerRegistry.proxy" ./contracts/deployments/core/local.json)
    fi
    if [ -z "${RUST_LOG+x}" ]; then
        export RUST_LOG="world_id_dev_client_rp=trace,world_id_dev_client_issuer_blinding=trace,world_id_oprf_dev_client=trace,taceo_oprf_dev_client=trace,taceo_oprf_client=trace,warn"
    fi

    if [[ $1 == "setup-test" ]]; then
        deploy_wip101_contracts
        RUST_LOG=$RUST_LOG cargo run --release --bin world-id-dev-client-rp -- --rp-id 123 --create-key test
        RUST_LOG=$RUST_LOG cargo run --release --bin world-id-dev-client-issuer-blinding -- --issuer-schema-id 124 --create-key test
        RUST_LOG=$RUST_LOG cargo run --release --bin world-id-dev-client-rp -- --rp-id 101 test 
        # so far it is not possible to call WIP101 with custom interface
        # RUST_LOG=$RUST_LOG cargo run --release --bin world-id-dev-client-rp -- --rp-id 102 test 
    else
        RUST_LOG=$RUST_LOG cargo run --release --bin world-id-dev-client-rp -- "$@"
        RUST_LOG=$RUST_LOG cargo run --release --bin world-id-dev-client-issuer-blinding -- "$@"
    fi
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
        client setup-test
    else
        echo "unknown command: '$1'"
        exit 1
    fi
}

main "$@"
