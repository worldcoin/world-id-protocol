# Testing recipes for Rust and Solidity.
# Uses CONTRACTS_DIR, PARALLEL_JOBS, WC_RPC, ETH_RPC from the root Justfile.

_FIXTURE_DIR := CONTRACTS_DIR / "test" / "crosschain" / "fixtures" / "e2e_mpt"
_IT_SCRIPT   := "script/crosschain/E2E_MPT.s.sol"
_IT_KEY      := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
_IT_FLAGS    := "--broadcast --private-key " + _IT_KEY + " --skip-simulation"
_IT_SLOT     := "0x8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00"

# Run all unit tests (parallel when GNU parallel is available), then e2e sequentially.
# Example:  just all
[group('test')]
all: _units it-all

# Backward-compatible alias for `just all`.
[group('test')]
test: all

# Run Rust workspace tests with nextest.
# Example:  just rust
#           just rust -- -E 'package(world-id-gateway)'
[group('test')]
rust *args='':
    cargo nextest run --workspace --test-threads {{ PARALLEL_JOBS }} {{ args }}

# Run core (non-crosschain) contract tests.
# Example:  just core
#           just core -- -vvv --match-test testFoo
[group('test')]
core *args='':
    cd {{ CONTRACTS_DIR }} && forge test --no-match-path 'test/crosschain/*' --jobs {{ PARALLEL_JOBS }} {{ args }}

# Run crosschain bridge contract tests.
# Example:  just crosschain
#           just crosschain -- -vvv
[group('test')]
crosschain *args='':
    cd {{ CONTRACTS_DIR }} && forge test --match-path 'test/crosschain/*' --jobs {{ PARALLEL_JOBS }} {{ args }}

# Run the full multi-anvil E2E MPT proof pipeline.
# Example:  just it
#           just it 50
[group('test')]
it batch='1': _it-start (_it-deploy batch) (_it-propagate batch) _it-extract-proofs _it-relay (_it-verify batch) _it-stop

# Run the E2E pipeline with batch sizes 1, 50, and 100.
# Example:  just it-all
[group('test')]
it-all:
    @just it "1"
    @just it "50"
    @just it "100"

# Stop anvils (manual cleanup if the pipeline fails mid-run).
# Example:  just stop
[group('test')]
stop: _it-stop

# Backward-compatible aliases for previous recipe names.
[group('test')]
test-world-id *args='':
    @just core {{ args }}

[group('test')]
test-bridge *args='':
    @just crosschain {{ args }}

[group('test')]
it-stop: _it-stop

# Run Rust + Solidity unit tests in parallel when available.
[private]
_units:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v parallel >/dev/null 2>&1; then
        parallel --jobs {{ PARALLEL_JOBS }} --line-buffer '{{ just_executable() }} {}' ::: rust core crosschain
    else
        echo "GNU parallel not found; running unit test suites sequentially."
        {{ just_executable() }} rust
        {{ just_executable() }} core
        {{ just_executable() }} crosschain
    fi

[private]
_it-start:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== Starting anvil instances ==="
    mkdir -p {{ _FIXTURE_DIR }}
    lsof -ti:{{ WC_PORT }} | xargs -r kill 2>/dev/null || true
    lsof -ti:{{ ETH_PORT }} | xargs -r kill 2>/dev/null || true
    sleep 0.5
    anvil --port {{ WC_PORT }} --chain-id 480 --silent &
    echo $! > {{ _FIXTURE_DIR }}/wc.pid
    anvil --port {{ ETH_PORT }} --chain-id 1 --silent &
    echo $! > {{ _FIXTURE_DIR }}/eth.pid
    for i in $(seq 1 30); do
        if cast chain-id --rpc-url {{ WC_RPC }} >/dev/null 2>&1 && \
           cast chain-id --rpc-url {{ ETH_RPC }} >/dev/null 2>&1; then
            echo "  World Chain (port {{ WC_PORT }}), Ethereum (port {{ ETH_PORT }})"
            exit 0
        fi
        sleep 0.2
    done
    echo "FAIL: Anvil instances did not start" && exit 1

[private]
_it-stop:
    #!/usr/bin/env bash
    echo "Cleaning up anvils..."
    [ -f {{ _FIXTURE_DIR }}/wc.pid ] && kill "$(cat {{ _FIXTURE_DIR }}/wc.pid)" 2>/dev/null || true
    [ -f {{ _FIXTURE_DIR }}/eth.pid ] && kill "$(cat {{ _FIXTURE_DIR }}/eth.pid)" 2>/dev/null || true
    rm -f {{ _FIXTURE_DIR }}/wc.pid {{ _FIXTURE_DIR }}/eth.pid

[private]
_it-deploy batch:
    @echo ""
    @echo "=== Phase 1: Deploy World Chain contracts (batch={{ batch }}) ==="
    cd {{ CONTRACTS_DIR }} && BATCH_SIZE={{ batch }} forge script {{ _IT_SCRIPT }}:DeployE2E --rpc-url {{ WC_RPC }} {{ _IT_FLAGS }}

[private]
_it-propagate batch:
    @echo ""
    @echo "=== Phase 2: Propagate state (batch={{ batch }}) ==="
    cd {{ CONTRACTS_DIR }} && BATCH_SIZE={{ batch }} forge script {{ _IT_SCRIPT }}:PropagateE2E --rpc-url {{ WC_RPC }} {{ _IT_FLAGS }}

[private]
_it-extract-proofs:
    #!/usr/bin/env bash
    set -euo pipefail
    echo ""
    echo "=== Phase 3: Extract MPT proofs and event data ==="
    SOURCE_PROXY=$(jq -r '.sourceProxy' {{ _FIXTURE_DIR }}/wc_addrs.json)

    # Mine a block to finalize state
    cast rpc anvil_mine 1 --rpc-url {{ WC_RPC }} > /dev/null

    # ── MPT proof ──
    PROOF_JSON=$(cast proof "$SOURCE_PROXY" {{ _IT_SLOT }} --rpc-url {{ WC_RPC }})
    STATE_ROOT=$(cast block latest --json --rpc-url {{ WC_RPC }} | jq -r '.stateRoot')
    echo "  State root: $STATE_ROOT"
    echo "  Chain head: $(echo "$PROOF_JSON" | jq -r '.storageProof[0].value')"
    jq -n \
        --arg stateRoot "$STATE_ROOT" \
        --argjson accountProof "$(echo "$PROOF_JSON" | jq '.accountProof')" \
        --argjson storageProof "$(echo "$PROOF_JSON" | jq '.storageProof[0].proof')" \
        '{stateRoot: $stateRoot, accountProof: $accountProof, storageProof: $storageProof}' \
        > {{ _FIXTURE_DIR }}/proof.json

    # ── ChainCommitted event data ──
    EVENT_TOPIC=$(cast sig-event "ChainCommitted(bytes32,uint256,uint256,bytes)")
    LOGS=$(cast rpc eth_getLogs "{\"fromBlock\":\"0x0\",\"address\":\"$SOURCE_PROXY\",\"topics\":[\"$EVENT_TOPIC\"]}" --rpc-url {{ WC_RPC }})

    EVENT_COUNT=$(echo "$LOGS" | jq 'length')
    echo "  ChainCommitted events: $EVENT_COUNT"

    for i in $(seq 0 $((EVENT_COUNT - 1))); do
        HEAD=$(echo "$LOGS" | jq -r ".[$i].topics[1]")
        DATA=$(echo "$LOGS" | jq -r ".[$i].data")
        ROUND=$((i + 1))
        jq -n --arg chainHead "$HEAD" --arg eventData "$DATA" \
            '{chainHead: $chainHead, eventData: $eventData}' \
            > {{ _FIXTURE_DIR }}/round${ROUND}.json
        echo "  Round $ROUND head: $HEAD"
    done

[private]
_it-relay:
    @echo ""
    @echo "=== Phase 4: Deploy Ethereum contracts and relay ==="
    cd {{ CONTRACTS_DIR }} && forge script {{ _IT_SCRIPT }}:DeployAndRelayE2E --rpc-url {{ ETH_RPC }} {{ _IT_FLAGS }}

[private]
_it-verify batch:
    @echo ""
    @echo "=== Phase 5: Verify final state ==="
    cd {{ CONTRACTS_DIR }} && BATCH_SIZE={{ batch }} forge script {{ _IT_SCRIPT }}:VerifyE2E --rpc-url {{ ETH_RPC }}
