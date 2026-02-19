set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

ROOT          := justfile_directory() / "../.."
CONTRACTS_DIR := ROOT / "contracts"
FIXTURE_DIR   := CONTRACTS_DIR / "test" / "crosschain" / "fixtures" / "e2e_relay"
_RELAY_SCRIPT := "script/crosschain/E2E_Relay.s.sol"

# Anvil ports & RPCs
WC_PORT   := "18545"
ETH_PORT  := "18546"
DEST_PORT := "18547"
WC_RPC    := "http://localhost:" + WC_PORT
ETH_RPC   := "http://localhost:" + ETH_PORT
DEST_RPC  := "http://localhost:" + DEST_PORT

# Anvil account #0 private key (deployer + relay signer + gateway owner)
_KEY := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Anvil account #1 private key (provisioner — separate to avoid nonce conflicts with the relay)
_PROVISIONER_KEY := "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
_BROADCAST := "--broadcast --private-key " + _KEY + " --skip-simulation --slow"

# L2ToL1MessagePasser predeploy (for output root computation)
_MSG_PASSER := "0x4200000000000000000000000000000000000016"

# ERC-7201 storage slot for keccak chain head
_STORAGE_SLOT := "0x8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00"

# ── Main entry point ────────────────────────────────────────────────────────

# Run the full relay E2E integration test (3 anvils + relay binary).
it: _start-anvils _deploy _run-test
    @just -f {{ justfile() }} _cleanup

# Manual cleanup if the test fails partway.
stop: _cleanup

# ── Anvil lifecycle ─────────────────────────────────────────────────────────

[private]
_start-anvils:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== Starting 3 anvil instances ==="
    mkdir -p {{ FIXTURE_DIR }}

    # Kill any stale instances
    for port in {{ WC_PORT }} {{ ETH_PORT }} {{ DEST_PORT }}; do
        lsof -ti:"$port" | xargs -r kill 2>/dev/null || true
    done
    sleep 0.5

    anvil --port {{ WC_PORT }}   --chain-id 480  --silent &
    echo $! > {{ FIXTURE_DIR }}/wc.pid

    anvil --port {{ ETH_PORT }}  --chain-id 1    --silent &
    echo $! > {{ FIXTURE_DIR }}/eth.pid

    anvil --port {{ DEST_PORT }} --chain-id 8453 --silent &
    echo $! > {{ FIXTURE_DIR }}/dest.pid

    # Wait for all three to become ready
    for i in $(seq 1 30); do
        if cast chain-id --rpc-url {{ WC_RPC }}   >/dev/null 2>&1 && \
           cast chain-id --rpc-url {{ ETH_RPC }}  >/dev/null 2>&1 && \
           cast chain-id --rpc-url {{ DEST_RPC }} >/dev/null 2>&1; then
            echo "  World Chain (:{{ WC_PORT }}), Ethereum (:{{ ETH_PORT }}), Dest (:{{ DEST_PORT }})"
            exit 0
        fi
        sleep 0.2
    done
    echo "FAIL: anvils did not become ready" && exit 1

[private]
_cleanup:
    #!/usr/bin/env bash
    echo "=== Cleaning up ==="
    for pidfile in {{ FIXTURE_DIR }}/relay.pid {{ FIXTURE_DIR }}/provisioner.pid {{ FIXTURE_DIR }}/updater.pid \
                   {{ FIXTURE_DIR }}/wc.pid {{ FIXTURE_DIR }}/eth.pid {{ FIXTURE_DIR }}/dest.pid; do
        [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
        rm -f "$pidfile"
    done

# ── Contract deployment ─────────────────────────────────────────────────────

[private]
_deploy:
    #!/usr/bin/env bash
    set -euo pipefail

    # Clean stale broadcast/cache artifacts so forge doesn't reuse wrong nonces
    rm -rf {{ CONTRACTS_DIR }}/broadcast/E2E_Relay.s.sol
    rm -rf {{ CONTRACTS_DIR }}/cache/E2E_Relay.s.sol

    echo ""
    echo "=== Phase 1: Deploy World Chain contracts ==="
    cd {{ CONTRACTS_DIR }} && forge script {{ _RELAY_SCRIPT }}:DeploySourceRelayE2E \
        --rpc-url {{ WC_RPC }} {{ _BROADCAST }}

    SOURCE_PROXY=$(jq -r '.sourceProxy' {{ FIXTURE_DIR }}/wc_addrs.json)

    echo ""
    echo "=== Phase 2a: Deploy L1 contracts (EthereumMPT) ==="
    cd {{ CONTRACTS_DIR }} && WC_SOURCE_PROXY="$SOURCE_PROXY" forge script \
        {{ _RELAY_SCRIPT }}:DeployEthRelayE2E \
        --rpc-url {{ ETH_RPC }} {{ _BROADCAST }}

    echo ""
    echo "=== Phase 2b: Deploy destination contracts (Permissioned) ==="
    cd {{ CONTRACTS_DIR }} && WC_SOURCE_PROXY="$SOURCE_PROXY" forge script \
        {{ _RELAY_SCRIPT }}:DeployDestRelayE2E \
        --rpc-url {{ DEST_RPC }} {{ _BROADCAST }}

    # Build destinations.json for the relay (dest chain only — ETH uses L1 MPT path)
    DEST_GW=$(jq -r '.gateway' {{ FIXTURE_DIR }}/dest_addrs.json)
    cat > {{ FIXTURE_DIR }}/destinations.json <<DEOF
    [
      {
        "chain_id": 8453,
        "rpc_url": "{{ DEST_RPC }}",
        "gateways": [
          { "type": "permissioned", "address": "$DEST_GW" }
        ]
      }
    ]
    DEOF

    echo ""
    echo "  destinations.json written"

# ── Test execution ──────────────────────────────────────────────────────────

[private]
_run-test:
    #!/usr/bin/env bash
    set -euo pipefail

    # ── Read deployed addresses ──
    SOURCE_PROXY=$(jq -r '.sourceProxy'   {{ FIXTURE_DIR }}/wc_addrs.json)
    REGISTRY=$(jq -r     '.registry'      {{ FIXTURE_DIR }}/wc_addrs.json)
    ISSUER_REG=$(jq -r   '.issuerRegistry' {{ FIXTURE_DIR }}/wc_addrs.json)

    ETH_SAT=$(jq -r   '.satelliteProxy'      {{ FIXTURE_DIR }}/eth_addrs.json)
    ETH_GW=$(jq -r    '.gateway'             {{ FIXTURE_DIR }}/eth_addrs.json)
    DGF=$(jq -r        '.disputeGameFactory' {{ FIXTURE_DIR }}/eth_addrs.json)
    MOCK_GAME=$(jq -r  '.disputeGame'        {{ FIXTURE_DIR }}/eth_addrs.json)

    DEST_SAT=$(jq -r '.satelliteProxy' {{ FIXTURE_DIR }}/dest_addrs.json)

    KEY="{{ _KEY }}"
    PROV_KEY="{{ _PROVISIONER_KEY }}"

    # ── Build the relay binary ──
    echo ""
    echo "=== Phase 3: Starting relay + background tasks ==="
    cargo build -p world-id-relay 2>&1 | tail -1

    # ── Start the game provisioner (background) ──
    # Watches WC state and provisions mock dispute games on ETH so the relay
    # can find them when it needs to build MPT proofs.
    (
        LAST_PROVISIONED=0
        while true; do
            sleep 3

            # Mine a block to finalize any pending state
            cast rpc anvil_mine 1 --rpc-url {{ WC_RPC }} > /dev/null 2>&1 || continue

            BLOCK_NUM=$(cast block-number --rpc-url {{ WC_RPC }} 2>/dev/null || echo "0")
            if [ "$BLOCK_NUM" = "$LAST_PROVISIONED" ] || [ "$BLOCK_NUM" = "0" ]; then
                continue
            fi

            # Get block data
            BLOCK_JSON=$(cast block latest --json --rpc-url {{ WC_RPC }} 2>/dev/null) || continue
            STATE_ROOT=$(echo "$BLOCK_JSON" | jq -r '.stateRoot')
            BLOCK_HASH=$(echo "$BLOCK_JSON" | jq -r '.hash')

            # Get L2ToL1MessagePasser storage hash
            MSG_PASSER_JSON=$(cast proof {{ _MSG_PASSER }} --rpc-url {{ WC_RPC }} 2>/dev/null) || continue
            MSG_PASSER_HASH=$(echo "$MSG_PASSER_JSON" | jq -r '.storageHash')

            # Compute output root = keccak256(version || stateRoot || msgPasserHash || blockHash)
            PREIMAGE=$(cast concat-hex \
                0x0000000000000000000000000000000000000000000000000000000000000000 \
                "$STATE_ROOT" "$MSG_PASSER_HASH" "$BLOCK_HASH")
            OUTPUT_ROOT=$(cast keccak "$PREIMAGE")

            # Update the mock dispute game on ETH (uses provisioner key to avoid nonce conflicts)
            cast send "$MOCK_GAME" "setRootClaim(bytes32)"    "$OUTPUT_ROOT" --rpc-url {{ ETH_RPC }} --private-key "$PROV_KEY" > /dev/null 2>&1
            cast send "$MOCK_GAME" "setL2BlockNumber(uint256)" "$BLOCK_NUM"  --rpc-url {{ ETH_RPC }} --private-key "$PROV_KEY" > /dev/null 2>&1
            cast send "$MOCK_GAME" "setStatus(uint8)"          0             --rpc-url {{ ETH_RPC }} --private-key "$PROV_KEY" > /dev/null 2>&1
            cast send "$MOCK_GAME" "setExtraData(bytes)"       0x            --rpc-url {{ ETH_RPC }} --private-key "$PROV_KEY" > /dev/null 2>&1

            # Register in factory (appends — relay scans from latest)
            cast send "$DGF" "addGame(uint32,address)" 0 "$MOCK_GAME" --rpc-url {{ ETH_RPC }} --private-key "$PROV_KEY" > /dev/null 2>&1

            LAST_PROVISIONED=$BLOCK_NUM
        done
    ) &
    echo $! > {{ FIXTURE_DIR }}/provisioner.pid
    echo "  Game provisioner PID: $(cat {{ FIXTURE_DIR }}/provisioner.pid)"

    # ── Start the relay binary ──
    cargo run -p world-id-relay -- \
        --rpc-url {{ WC_RPC }} \
        --wc-source-address "$SOURCE_PROXY" \
        --wallet-private-key "$KEY" \
        --issuer-schema-ids 1 \
        --oprf-key-ids 1 \
        --propagation-interval 5s \
        --event-poll-interval 2s \
        --l1-rpc-url {{ ETH_RPC }} \
        --l1-gateway-address "$ETH_GW" \
        --l1-satellite-address "$ETH_SAT" \
        --dispute-game-factory "$DGF" \
        --game-type 0 \
        --dispute-game-poll-interval 3s \
        --dispute-game-timeout 60s \
        --destinations-config {{ FIXTURE_DIR }}/destinations.json \
        2>&1 | tee {{ FIXTURE_DIR }}/relay.log | sed 's/^/  [relay] /' &
    echo $! > {{ FIXTURE_DIR }}/relay.pid
    echo "  Relay PID: $(cat {{ FIXTURE_DIR }}/relay.pid)"

    # Give the relay a moment to start
    sleep 2

    # ── Wait for round 1 (root=1000) ──
    echo ""
    echo "=== Phase 4: Waiting for round 1 (root=1000) ==="

    ROUND1_OK=false
    for i in $(seq 1 45); do
        ETH_ROOT=$(cast call "$ETH_SAT" "LATEST_ROOT()(uint256)" --rpc-url {{ ETH_RPC }} 2>/dev/null || echo "0")
        DEST_ROOT=$(cast call "$DEST_SAT" "LATEST_ROOT()(uint256)" --rpc-url {{ DEST_RPC }} 2>/dev/null || echo "0")

        if [ "$ETH_ROOT" = "1000" ] && [ "$DEST_ROOT" = "1000" ]; then
            echo "  ETH root=1000 ✓  DEST root=1000 ✓  (${i}s)"
            ROUND1_OK=true
            break
        fi
        sleep 1
    done

    if [ "$ROUND1_OK" != "true" ]; then
        echo "FAIL: round 1 did not arrive within 45s (ETH=$ETH_ROOT, DEST=$DEST_ROOT)"
        exit 1
    fi

    # ── Update registries (trigger round 2) ──
    echo ""
    echo "=== Phase 5: Updating registries for round 2 ==="
    cast send "$REGISTRY"   "setLatestRoot(uint256)"                 2000    --rpc-url {{ WC_RPC }} --private-key "$PROV_KEY" > /dev/null
    cast send "$ISSUER_REG" "setPubkey(uint64,uint256,uint256)" 1 55 66      --rpc-url {{ WC_RPC }} --private-key "$PROV_KEY" > /dev/null
    echo "  Registry updated: root=2000, issuer#1=(55,66)"

    # ── Wait for round 2 (root=2000) ──
    echo ""
    echo "=== Phase 6: Waiting for round 2 (root=2000) ==="

    ROUND2_OK=false
    for i in $(seq 1 45); do
        ETH_ROOT=$(cast call "$ETH_SAT" "LATEST_ROOT()(uint256)" --rpc-url {{ ETH_RPC }} 2>/dev/null || echo "0")
        DEST_ROOT=$(cast call "$DEST_SAT" "LATEST_ROOT()(uint256)" --rpc-url {{ DEST_RPC }} 2>/dev/null || echo "0")

        if [ "$ETH_ROOT" = "2000" ] && [ "$DEST_ROOT" = "2000" ]; then
            echo "  ETH root=2000 ✓  DEST root=2000 ✓  (${i}s)"
            ROUND2_OK=true
            break
        fi
        sleep 1
    done

    if [ "$ROUND2_OK" != "true" ]; then
        echo "FAIL: round 2 did not arrive within 45s (ETH=$ETH_ROOT, DEST=$DEST_ROOT)"
        exit 1
    fi

    # ── Verify final state ──
    echo ""
    echo "=== Phase 7: Verifying final state ==="
    PASS=true

    for LABEL_RPC in "ETH|{{ ETH_RPC }}|$ETH_SAT" "DEST|{{ DEST_RPC }}|$DEST_SAT"; do
        LABEL=$(echo "$LABEL_RPC" | cut -d'|' -f1)
        RPC="$(echo "$LABEL_RPC" | cut -d'|' -f2)"
        SAT=$(echo "$LABEL_RPC" | cut -d'|' -f3)

        ROOT=$(cast call "$SAT" "LATEST_ROOT()(uint256)" --rpc-url "$RPC")
        if [ "$ROOT" = "2000" ]; then echo "  $LABEL LATEST_ROOT=2000 ✓"
        else echo "  $LABEL LATEST_ROOT=$ROOT ✗ (expected 2000)"; PASS=false; fi

        # Check issuer #1 pubkey (updated to 55, 66)
        ISSUER_RAW=$(cast call "$SAT" "issuerSchemaIdToPubkeyAndProofId(uint64)((uint256,uint256),bytes32)" 1 --rpc-url "$RPC")
        if echo "$ISSUER_RAW" | grep -q "55" && echo "$ISSUER_RAW" | grep -q "66"; then
            echo "  $LABEL issuer#1=(55,66) ✓"
        else
            echo "  $LABEL issuer#1 ✗ got: $ISSUER_RAW"
            PASS=false
        fi

        # Check oprf #1 pubkey (unchanged: 13, 14)
        OPRF_RAW=$(cast call "$SAT" "oprfKeyIdToPubkeyAndProofId(uint160)((uint256,uint256),bytes32)" 1 --rpc-url "$RPC")
        if echo "$OPRF_RAW" | grep -q "13" && echo "$OPRF_RAW" | grep -q "14"; then
            echo "  $LABEL oprf#1=(13,14) ✓"
        else
            echo "  $LABEL oprf#1 ✗ got: $OPRF_RAW"
            PASS=false
        fi

        # Check keccak chain head is non-zero (state was bridged)
        CHAIN_HEAD=$(cast call "$SAT" "KECCAK_CHAIN()((bytes32,uint64))" --rpc-url "$RPC" 2>/dev/null || echo "0x0")
        if echo "$CHAIN_HEAD" | grep -qv "0x0000000000000000000000000000000000000000000000000000000000000000"; then
            echo "  $LABEL chain head ✓"
        else
            echo "  $LABEL chain head ✗ (zero)"
            PASS=false
        fi
    done

    echo ""
    if [ "$PASS" = "true" ]; then
        echo "=== ALL ASSERTIONS PASSED ==="
    else
        echo "=== SOME ASSERTIONS FAILED ==="
        exit 1
    fi
