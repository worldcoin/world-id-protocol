# Deploy, verify & admin recipes.
# Imported by the root Justfile. Uses BRIDGE_DIR, CONTRACTS_DIR, ENV,
# PRIVATE_KEY, and other variables from root scope.

alias d := deploy
alias s := status

# Deploy all (or filter with DEPLOY_CHAINS=ethereum)
[group('deploy')]
deploy env=ENV *args='':
    cd {{ BRIDGE_DIR }} && forge script script/Deploy.s.sol:Deploy \
        --sig "run(string)" "{{ env }}" --multi --broadcast {{ args }}

# Simulate deployment (no broadcast)
[group('deploy')]
dry-run env=ENV *args='':
    cd {{ BRIDGE_DIR }} && forge script script/Deploy.s.sol:Deploy \
        --sig "run(string)" "{{ env }}" --multi {{ args }}

# Show deployment artifact
[group('deploy')]
status env=ENV:
    @jq '.' {{ BRIDGE_DIR }}/deployments/{{ env }}.json 2>/dev/null || echo "No deployment found for '{{ env }}'."

# Verify deployed contracts on block explorers
[group('deploy')]
verify chain env=ENV:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg="{{ BRIDGE_DIR }}/script/config/{{ env }}.json"
    deploy="{{ BRIDGE_DIR }}/deployments/{{ env }}.json"
    [ -f "$deploy" ] || { echo "No deployment at $deploy"; exit 1; }
    [ -n "${ETHERSCAN_API_KEY:-}" ] || { echo "Set ETHERSCAN_API_KEY"; exit 1; }

    slug=$(jq -r '.{{ chain }}.alchemySlug // empty' "$cfg")
    rpc=$(jq -r '.{{ chain }}.rpc // empty' "$cfg")
    if [ -n "${ALCHEMY_API_KEY:-}" ] && [ -n "$slug" ]; then
        rpc="https://${slug}.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
    fi

    _verify() { echo "  $2 @ $1"; forge verify-contract "$1" "$2" --rpc-url "$rpc" --etherscan-api-key "$ETHERSCAN_API_KEY" --watch || echo "    (may already be verified)"; }

    echo "{{ chain }}"
    if [ "{{ chain }}" = "worldchain" ]; then
        addr=$(jq -r '.worldchain.worldIDSource.implementation // empty' "$deploy")
        [ -n "$addr" ] && _verify "$addr" "WorldIDSource"
    else
        addr=$(jq -r '.{{ chain }}.worldIDSatellite.implementation // empty' "$deploy")
        [ -n "$addr" ] && _verify "$addr" "WorldIDSatellite"
        addr=$(jq -r '.{{ chain }}.verifier // empty' "$deploy")
        [ -n "$addr" ] && [ "$addr" != "0x0000000000000000000000000000000000000000" ] && _verify "$addr" "Verifier"
        for gw in permissionedGateway:PermissionedGatewayAdapter ethereumMPTGateway:EthereumMPTGatewayAdapter lightClientGateway:LightClientGatewayAdapter; do
            key="${gw%%:*}"; name="${gw##*:}"
            addr=$(jq -r ".{{ chain }}.gateways.${key} // empty" "$deploy")
            [ -n "$addr" ] && _verify "$addr" "$name"
        done
    fi

# Authorize a gateway on a satellite
[group('deploy')]
[confirm("Authorize gateway?")]
authorize chain gateway env=ENV:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg="{{ BRIDGE_DIR }}/script/config/{{ env }}.json"
    deploy="{{ BRIDGE_DIR }}/deployments/{{ env }}.json"
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy // empty' "$deploy")
    [ -n "$proxy" ] || { echo "No WorldIDSatellite for {{ chain }}"; exit 1; }
    slug=$(jq -r '.{{ chain }}.alchemySlug // empty' "$cfg")
    rpc=$(jq -r '.{{ chain }}.rpc // empty' "$cfg")
    [ -n "${ALCHEMY_API_KEY:-}" ] && [ -n "$slug" ] && rpc="https://${slug}.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
    echo "Authorizing {{ gateway }} on {{ chain }} (satellite: $proxy)"
    cast send "$proxy" "addGateway(address)" "{{ gateway }}" --rpc-url "$rpc" --private-key "$PRIVATE_KEY"

# Revoke a gateway from a satellite
[group('deploy')]
[confirm("Revoke gateway?")]
revoke chain gateway env=ENV:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg="{{ BRIDGE_DIR }}/script/config/{{ env }}.json"
    deploy="{{ BRIDGE_DIR }}/deployments/{{ env }}.json"
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy // empty' "$deploy")
    [ -n "$proxy" ] || { echo "No WorldIDSatellite for {{ chain }}"; exit 1; }
    slug=$(jq -r '.{{ chain }}.alchemySlug // empty' "$cfg")
    rpc=$(jq -r '.{{ chain }}.rpc // empty' "$cfg")
    [ -n "${ALCHEMY_API_KEY:-}" ] && [ -n "$slug" ] && rpc="https://${slug}.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
    echo "Revoking {{ gateway }} on {{ chain }} (satellite: $proxy)"
    cast send "$proxy" "removeGateway(address)" "{{ gateway }}" --rpc-url "$rpc" --private-key "$PRIVATE_KEY"

# Transfer contract ownership
[group('deploy')]
[confirm("Transfer ownership?")]
transfer chain contract_addr new_owner env=ENV:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg="{{ BRIDGE_DIR }}/script/config/{{ env }}.json"
    slug=$(jq -r '.{{ chain }}.alchemySlug // empty' "$cfg")
    rpc=$(jq -r '.{{ chain }}.rpc // empty' "$cfg")
    [ -n "${ALCHEMY_API_KEY:-}" ] && [ -n "$slug" ] && rpc="https://${slug}.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
    echo "Transferring ownership of {{ contract_addr }} to {{ new_owner }} on {{ chain }}"
    cast send "{{ contract_addr }}" "transferOwnership(address)" "{{ new_owner }}" --rpc-url "$rpc" --private-key "$PRIVATE_KEY"
