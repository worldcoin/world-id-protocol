#!/usr/bin/env bash

# Clean up stale cache from previous runs
# echo "Cleaning up stale cache files..."
# rm -f /tmp/tree.mmap /tmp/tree.mmap.meta

set -eu

PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Canonical Multicall3 address (same on all EVM chains).
MULTICALL3_ADDR=0xcA11bde05977b3631167028862bE2a173976CA11
# Multicall3 runtime bytecode (from mainnet).
MULTICALL3_BYTECODE=0x6080604052600436106100f35760003560e01c80634d2301cc1161008a578063a8b0574e11610059578063a8b0574e1461025a578063bce38bd714610275578063c3077fa914610288578063ee82ac5e1461029b57600080fd5b80634d2301cc146101ec57806372425d9d1461022157806382ad56cb1461023457806386d516e81461024757600080fd5b80633408e470116100c65780633408e47014610191578063399542e9146101a45780633e64a696146101c657806342cbb15c146101d957600080fd5b80630f28c97d146100f8578063174dea711461011a578063252dba421461013a57806327e86d6e1461015b575b600080fd5b34801561010457600080fd5b50425b6040519081526020015b60405180910390f35b61012d610128366004610a85565b6102ba565b6040516101119190610bbe565b61014d610148366004610a85565b6104ef565b604051610111929190610bd8565b34801561016757600080fd5b50437fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0140610107565b34801561019d57600080fd5b5046610107565b6101b76101b2366004610c60565b610690565b60405161011193929190610cba565b3480156101d257600080fd5b5048610107565b3480156101e557600080fd5b5043610107565b3480156101f857600080fd5b50610107610207366004610ce2565b73ffffffffffffffffffffffffffffffffffffffff163190565b34801561022d57600080fd5b5044610107565b61012d610242366004610a85565b6106ab565b34801561025357600080fd5b5045610107565b34801561026657600080fd5b50604051418152602001610111565b61012d610283366004610c60565b61085a565b6101b7610296366004610a85565b610a1a565b3480156102a757600080fd5b506101076102b6366004610d18565b4090565b60606000828067ffffffffffffffff8111156102d8576102d8610d31565b60405190808252806020026020018201604052801561031e57816020015b6040805180820190915260008152606060208201528152602001906001900390816102f65790505b5092503660005b8281101561047757600085828151811061034157610341610d60565b6020026020010151905087878381811061035d5761035d610d60565b905060200281019061036f9190610d8f565b6040810135958601959093506103886020850185610ce2565b73ffffffffffffffffffffffffffffffffffffffff16816103ac6060870187610dcd565b6040516103ba929190610e32565b60006040518083038185875af1925050503d80600081146103f7576040519150601f19603f3d011682016040523d82523d6000602084013e6103fc565b606091505b50602080850191909152901515808452908501351761046d577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260846000fd5b5050600101610325565b508234146104e6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601a60248201527f4d756c746963616c6c333a2076616c7565206d69736d6174636800000000000060448201526064015b60405180910390fd5b50505092915050565b436060828067ffffffffffffffff81111561050c5761050c610d31565b60405190808252806020026020018201604052801561053f57816020015b606081526020019060019003908161052a5790505b5091503660005b8281101561068657600087878381811061056257610562610d60565b90506020028101906105749190610e42565b92506105836020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166105a66020850185610dcd565b6040516105b4929190610e32565b6000604051808303816000865af19150503d80600081146105f1576040519150601f19603f3d011682016040523d82523d6000602084013e6105f6565b606091505b5086848151811061060957610609610d60565b602090810291909101015290508061067d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b50600101610546565b5050509250929050565b43804060606106a086868661085a565b905093509350939050565b6060818067ffffffffffffffff8111156106c7576106c7610d31565b60405190808252806020026020018201604052801561070d57816020015b6040805180820190915260008152606060208201528152602001906001900390816106e55790505b5091503660005b828110156104e657600084828151811061073057610730610d60565b6020026020010151905086868381811061074c5761074c610d60565b905060200281019061075e9190610e76565b925061076d6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166107906040850185610dcd565b60405161079e929190610e32565b6000604051808303816000865af19150503d80600081146107db576040519150601f19603f3d011682016040523d82523d6000602084013e6107e0565b606091505b506020808401919091529015158083529084013517610851577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260646000fd5b50600101610714565b6060818067ffffffffffffffff81111561087657610876610d31565b6040519080825280602002602001820160405280156108bc57816020015b6040805180820190915260008152606060208201528152602001906001900390816108945790505b5091503660005b82811015610a105760008482815181106108df576108df610d60565b602002602001015190508686838181106108fb576108fb610d60565b905060200281019061090d9190610e42565b925061091c6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff1661093f6020850185610dcd565b60405161094d929190610e32565b6000604051808303816000865af19150503d806000811461098a576040519150601f19603f3d011682016040523d82523d6000602084013e61098f565b606091505b506020830152151581528715610a07578051610a07576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b506001016108c3565b5050509392505050565b6000806060610a2b60018686610690565b919790965090945092505050565b60008083601f840112610a4b57600080fd5b50813567ffffffffffffffff811115610a6357600080fd5b6020830191508360208260051b8501011115610a7e57600080fd5b9250929050565b60008060208385031215610a9857600080fd5b823567ffffffffffffffff811115610aaf57600080fd5b610abb85828601610a39565b90969095509350505050565b6000815180845260005b81811015610aed57602081850181015186830182015201610ad1565b81811115610aff576000602083870101525b50601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169290920160200192915050565b600082825180855260208086019550808260051b84010181860160005b84811015610bb1578583037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe001895281518051151584528401516040858501819052610b9d81860183610ac7565b9a86019a9450505090830190600101610b4f565b5090979650505050505050565b602081526000610bd16020830184610b32565b9392505050565b600060408201848352602060408185015281855180845260608601915060608160051b870101935082870160005b82811015610c52577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0888703018452610c40868351610ac7565b95509284019290840190600101610c06565b509398975050505050505050565b600080600060408486031215610c7557600080fd5b83358015158114610c8557600080fd5b9250602084013567ffffffffffffffff811115610ca157600080fd5b610cad86828701610a39565b9497909650939450505050565b838152826020820152606060408201526000610cd96060830184610b32565b95945050505050565b600060208284031215610cf457600080fd5b813573ffffffffffffffffffffffffffffffffffffffff81168114610bd157600080fd5b600060208284031215610d2a57600080fd5b5035919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81833603018112610dc357600080fd5b9190910192915050565b60008083357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1843603018112610e0257600080fd5b83018035915067ffffffffffffffff821115610e1d57600080fd5b602001915036819003821315610a7e57600080fd5b8183823760009101908152919050565b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc1833603018112610dc357600080fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa1833603018112610dc357600080fdfea2646970667358221220bb2b5c71a328032f97c676ae39a1ec2148d3e5d6f73d95e9b17910152d61f16264736f6c634300080c0033

if [[ -n "${RELEASE:-}" ]]; then
    CARGO_BUILD_ARGS=(--release)
    BUILD_TARGET_DIR="release"
else
    CARGO_BUILD_ARGS=()
    BUILD_TARGET_DIR="debug"
fi

build_all() {
    echo "building all artifacts (${BUILD_TARGET_DIR}).."
    cargo build "${CARGO_BUILD_ARGS[@]+"${CARGO_BUILD_ARGS[@]}"}" \
        -p world-id-oprf-node \
        -p world-id-indexer \
        -p world-id-gateway \
        -p world-id-oprf-dev-client
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
            echo "error: $name did not become healthy after $timeout seconds" >&2
            exit 1
        fi
        sleep 1
    done
}

wait_for_anvil() {
    local timeout=${1:-30}
    local start_time=$(date +%s)
    echo "waiting for anvil on port 8545..."

    while true; do
        if cast chain-id --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1; then
            echo "anvil is up!"
            break
        fi
        now=$(date +%s)
        if (( now - start_time >= timeout )); then
            echo "error: anvil did not start after $timeout seconds" >&2
            exit 1
        fi
        sleep 1
    done
}

deploy_multicall3() {
    cast rpc anvil_setCode "$MULTICALL3_ADDR" "$MULTICALL3_BYTECODE" --rpc-url http://127.0.0.1:8545 >/dev/null
    local code
    code=$(cast code "$MULTICALL3_ADDR" --rpc-url http://127.0.0.1:8545)
    if [[ "$code" == "0x" || -z "$code" ]]; then
        echo "error: failed to etch Multicall3 bytecode" >&2
        exit 1
    fi
    echo "Multicall3 etched at $MULTICALL3_ADDR"
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
    TACEO_OPRF_NODE__SERVICE__OPRF__VERSION_REQ=">=0.0.0" \
    TACEO_OPRF_NODE__SERVICE__OPRF__STORE_TTL=0s \
    TACEO_OPRF_NODE__SERVICE__OPRF__STORE_TTI=0s \
    TACEO_OPRF_NODE__SERVICE__RPC__HTTP_URLS=http://127.0.0.1:8545 \
    TACEO_OPRF_NODE__SERVICE__RPC__CHAIN_ID=31337 \
    TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING=$db_conn \
    TACEO_OPRF_NODE__POSTGRES__SCHEMA=oprf$i \
    ./target/${BUILD_TARGET_DIR}/world-id-oprf-node > logs/node$i.log 2>&1 &
    pid=$!
    echo "started world-id-oprf-node $i with PID $pid"
}

run_indexer_and_gateway() {
    # remove the tree_cache_file as we have a new DB everytime we run local_setup
    rm -f /tmp/tree.mmap
    REGISTRY_ADDRESS=$world_id_registry RPC_URL=http://localhost:8545 WS_URL=ws://localhost:8545 DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres TREE_CACHE_FILE=/tmp/tree.mmap ./target/${BUILD_TARGET_DIR}/world-id-indexer --http --indexer > logs/world-id-indexer.log 2>&1 &
    indexer_pid=$!
    echo "started indexer with PID $indexer_pid"
    wait_for_health 8080 "world-id-indexer" 300

    REGISTRY_ADDRESS=$world_id_registry REGISTRY_VERSION=v1 RPC_URL=http://localhost:8545 WALLET_PRIVATE_KEY=$PK REDIS_URL=redis://localhost:6379 ./target/${BUILD_TARGET_DIR}/world-id-gateway > logs/world-id-gateway.log 2>&1 &
    gateway_pid=$!
    echo "started gateway with PID $gateway_pid"
    wait_for_health 8081 "world-id-gateway" 300
}

teardown() {
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
    wait_for_anvil
    deploy_multicall3

    docker compose up -d postgres redis

    echo "deploying contracts.."
    deploy_contracts

    echo "starting world-id-indexer and world-id-gateway.."
    run_indexer_and_gateway

    echo "starting OPRF key-gen nodes.."
    TACEO_OPRF_KEY_GEN__SERVICE__OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry docker compose up -d oprf-key-gen0 oprf-key-gen1 oprf-key-gen2
    docker compose logs -f oprf-key-gen0 > logs/key-gen0.log 2>&1 &
    docker compose logs -f oprf-key-gen1 > logs/key-gen1.log 2>&1 &
    docker compose logs -f oprf-key-gen2 > logs/key-gen2.log 2>&1 &
    wait_for_health 20000 "oprf-key-gen0" 300
    wait_for_health 20001 "oprf-key-gen1" 300
    wait_for_health 20002 "oprf-key-gen2" 300

    echo "starting OPRF nodes.."
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
        export TACEO_ADMIN_PRIVATE_KEY=$PK
        deploy_wip101_contracts
        RUST_LOG=$RUST_LOG ./target/${BUILD_TARGET_DIR}/world-id-dev-client-rp --rp-id 123 --create-key test
        RUST_LOG=$RUST_LOG ./target/${BUILD_TARGET_DIR}/world-id-dev-client-issuer-blinding --issuer-schema-id 124 --create-key test
        RUST_LOG=$RUST_LOG ./target/${BUILD_TARGET_DIR}/world-id-dev-client-rp --rp-id 101 test
        # so far it is not possible to call WIP101 with custom interface
        # RUST_LOG=$RUST_LOG ./target/${BUILD_TARGET_DIR}/world-id-dev-client-rp --rp-id 102 test
    else
        RUST_LOG=$RUST_LOG ./target/${BUILD_TARGET_DIR}/world-id-dev-client-rp "$@"
        RUST_LOG=$RUST_LOG ./target/${BUILD_TARGET_DIR}/world-id-dev-client-issuer-blinding "$@"
    fi
}

main() {
    if [ $# -lt 1 ]; then
        echo "usage: $0 <command>"
        exit 1
    fi

    build_all

    if [[ $1 = "setup" ]]; then
        echo "running setup.."
        setup
        echo "press Ctrl+C to stop"
        wait
    elif [[ $1 = "client" ]]; then
        echo "running client.."
        client "${@:2}"
    elif [[ $1 = "test" ]]; then
        echo "running test.."
        setup
        client setup-test
    else
        echo "unknown command: '$1'"
        exit 1
    fi
}

main "$@"
