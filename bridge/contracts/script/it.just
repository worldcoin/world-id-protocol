FIXTURE_DIR   := BRIDGE_DIR / "test" / "fixtures" / "e2e_mpt"
_IT_SCRIPT    := "script/E2E_MPT.s.sol"

_IT_KEY       := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
_IT_FLAGS     := "--broadcast --private-key " + _IT_KEY + " --skip-simulation"

STORAGE_SLOT  := "0x8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00"


# Run the full multi-anvil E2E MPT proof test.
[group('test')]
it batch='1': _start-anvils (_it-deploy batch) (_it-propagate batch) _it-extract-proofs _it-relay (_it-verify batch) _stop-anvils

[group('test')]
it-all: 
    @just it "1"
    @just it "50"
    @just it "100"    

# Stop anvils (manual cleanup if pipeline fails).
[group('test')]
it-stop: _stop-anvils

[private]
_start-anvils:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== Starting anvil instances ==="
    mkdir -p {{ FIXTURE_DIR }}
    lsof -ti:{{ WC_PORT }} | xargs -r kill 2>/dev/null || true
    lsof -ti:{{ ETH_PORT }} | xargs -r kill 2>/dev/null || true
    sleep 0.5
    anvil --port {{ WC_PORT }} --chain-id 480 --silent &
    echo $! > {{ FIXTURE_DIR }}/wc.pid
    anvil --port {{ ETH_PORT }} --chain-id 1 --silent &
    echo $! > {{ FIXTURE_DIR }}/eth.pid
    for i in $(seq 1 30); do
        if cast chain-id --rpc-url {{ WC_RPC }} >/dev/null 2>&1 && \
           cast chain-id --rpc-url {{ ETH_RPC }} >/dev/null 2>&1; then
            echo "  World Chain (port {{ WC_PORT }}), Ethereum (port {{ ETH_PORT }})"
            exit 0
        fi
        sleep 0.2
    done
    echo "FAIL: Anvil instances did not become ready" && exit 1

[private]
_stop-anvils:
    #!/usr/bin/env bash
    echo "Cleaning up anvils..."
    [ -f {{ FIXTURE_DIR }}/wc.pid ] && kill "$(cat {{ FIXTURE_DIR }}/wc.pid)" 2>/dev/null || true
    [ -f {{ FIXTURE_DIR }}/eth.pid ] && kill "$(cat {{ FIXTURE_DIR }}/eth.pid)" 2>/dev/null || true
    rm -f {{ FIXTURE_DIR }}/wc.pid {{ FIXTURE_DIR }}/eth.pid

[private]
_it-deploy batch:
    @echo ""
    @echo "=== Phase 1: Deploy World Chain contracts (batch={{ batch }}) ==="
    cd {{ BRIDGE_DIR }} && BATCH_SIZE={{ batch }} forge script {{ _IT_SCRIPT }}:DeployE2E --rpc-url {{ WC_RPC }} {{ _IT_FLAGS }}

[private]
_it-propagate batch:
    @echo ""
    @echo "=== Phase 2: Propagate state (batch={{ batch }}) ==="
    cd {{ BRIDGE_DIR }} && BATCH_SIZE={{ batch }} forge script {{ _IT_SCRIPT }}:PropagateE2E --rpc-url {{ WC_RPC }} {{ _IT_FLAGS }}

[private]
_it-extract-proofs:
    #!/usr/bin/env bash
    set -euo pipefail
    echo ""
    echo "=== Phase 3: Extract MPT proofs and event data ==="
    SOURCE_PROXY=$(jq -r '.sourceProxy' {{ FIXTURE_DIR }}/wc_addrs.json)

    # Mine a block to finalize state
    cast rpc anvil_mine 1 --rpc-url {{ WC_RPC }} > /dev/null

    # ── MPT proof ──
    PROOF_JSON=$(cast proof "$SOURCE_PROXY" {{ STORAGE_SLOT }} --rpc-url {{ WC_RPC }})
    STATE_ROOT=$(cast block latest --json --rpc-url {{ WC_RPC }} | jq -r '.stateRoot')
    echo "  State root: $STATE_ROOT"
    echo "  Chain head: $(echo "$PROOF_JSON" | jq -r '.storageProof[0].value')"
    jq -n \
        --arg stateRoot "$STATE_ROOT" \
        --argjson accountProof "$(echo "$PROOF_JSON" | jq '.accountProof')" \
        --argjson storageProof "$(echo "$PROOF_JSON" | jq '.storageProof[0].proof')" \
        '{stateRoot: $stateRoot, accountProof: $accountProof, storageProof: $storageProof}' \
        > {{ FIXTURE_DIR }}/proof.json

    # ── ChainCommitted event data (needed for relay) ──
    # Commitment data includes block-dependent fields (blockhash, block.number) so
    # it must be extracted from actual on-chain events, not forge simulation logs.
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
            > {{ FIXTURE_DIR }}/round${ROUND}.json
        echo "  Round $ROUND head: $HEAD"
    done

# ── Phase 4: Deploy Ethereum contracts + relay ─────────────────────────────

[private]
_it-relay:
    @echo ""
    @echo "=== Phase 4: Deploy Ethereum contracts and relay ==="
    cd {{ BRIDGE_DIR }} && forge script {{ _IT_SCRIPT }}:DeployAndRelayE2E --rpc-url {{ ETH_RPC }} {{ _IT_FLAGS }}

# ── Phase 5: Verify final state ───────────────────────────────────────────

[private]
_it-verify batch:
    @echo ""
    @echo "=== Phase 5: Verify final state ==="
    cd {{ BRIDGE_DIR }} && BATCH_SIZE={{ batch }} forge script {{ _IT_SCRIPT }}:VerifyE2E --rpc-url {{ ETH_RPC }}
