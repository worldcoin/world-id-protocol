# World ID on-chain operations.
#
# All contract addresses are resolved automatically from the deployment artifact
# for the given environment (staging | production | local).

# Simulate a contract call without broadcasting.
# Usage: just _cast-dry-run <rpc> <proxy> <sig> [calldata...]
# Example: just _cast-dry-run "$rpc" "$proxy" "addGateway(address)" 0xGateway
[private]
_cast-dry-run rpc proxy sig *args:
    #!/usr/bin/env bash
    set -euo pipefail
    caller=$(cast wallet address --private-key "$PRIVATE_KEY")
    cast call "$2" "$3" "${@:4}" --from "$caller" --rpc-url "$1"
    echo "✓ simulation passed"

# Dry-run first, then broadcast. Aborts if simulation reverts.
# Usage: just _cast-send <rpc> <proxy> <sig> [calldata...]
# Example: just _cast-send "$rpc" "$proxy" "addGateway(address)" 0xGateway
[private]
_cast-send rpc proxy sig *args:
    #!/usr/bin/env bash
    set -euo pipefail
    caller=$(cast wallet address --private-key "$PRIVATE_KEY")
    echo "Simulating..."
    cast call "$2" "$3" "${@:4}" --from "$caller" --rpc-url "$1" \
        || { echo "error: simulation reverted — aborting broadcast"; exit 1; }
    echo "✓ simulation passed — broadcasting"
    cast send "$2" "$3" "${@:4}" --private-key "$PRIVATE_KEY" --rpc-url "$1"

# ─────────────────────────────────────────────────────────────────────────────
# core · deploy
# ─────────────────────────────────────────────────────────────────────────────

# Simulate core contract deployment on World Chain (no broadcast).
# Example:
#   PRIVATE_KEY=0x... just _core-deploy-dry-run
#   PRIVATE_KEY=0x... just _core-deploy-dry-run production
[private]
_core-deploy-dry-run env='staging':
    cd {{ CONTRACTS_DIR }} && GIT_COMMIT=$(git -C {{ ROOT }} rev-parse HEAD) \
        forge script {{ CORE_SCRIPT }} \
        --sig "run(string)" "{{ env }}" \
        --private-key "$PRIVATE_KEY" \
        --rpc-url "{{ WORLDCHAIN_RPC }}"

# Deploy core contracts to World Chain (simulates first, then broadcasts).
# Writes artifact to deployments/core/{env}.json.
# Example:
#   PRIVATE_KEY=0x... VERIFIER_API_KEY=... just core-deploy
#   PRIVATE_KEY=0x... VERIFIER_API_KEY=... just core-deploy production
[group('core · deploy')]
[confirm("Deploy core contracts to {{ env }}?")]
core-deploy env='staging': (_core-deploy-dry-run env)
    cd {{ CONTRACTS_DIR }} && GIT_COMMIT=$(git -C {{ ROOT }} rev-parse HEAD) \
        forge script {{ CORE_SCRIPT }} \
        --sig "run(string)" "{{ env }}" \
        --private-key "$PRIVATE_KEY" \
        --rpc-url "{{ WORLDCHAIN_RPC }}" \
        --chain {{ WORLDCHAIN_CHAIN }} \
        --broadcast \
        --verify \
        --verifier etherscan \
        --verifier-url "{{ VERIFIER_URL }}" \
        --etherscan-api-key "$VERIFIER_API_KEY"

# ─────────────────────────────────────────────────────────────────────────────
# core · upgrade
# ─────────────────────────────────────────────────────────────────────────────

# Simulate upgrading WorldIDRegistry proxy.
# Example:  PRIVATE_KEY=0x... just _core-upgrade-world-id-registry staging
[private]
_core-upgrade-world-id-registry env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.worldIDRegistry.proxy' "$deploy")
    impl=$(jq -r '.worldIDRegistry.implementation' "$deploy")
    echo "Simulating: WorldIDRegistry $proxy → $impl"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Upgrade WorldIDRegistry proxy to the implementation in the deployment artifact.
# Example:  PRIVATE_KEY=0x... just core-upgrade-world-id-registry
#           PRIVATE_KEY=0x... just core-upgrade-world-id-registry production
[group('core · upgrade')]
[confirm("Upgrade WorldIDRegistry on {{ env }}?")]
core-upgrade-world-id-registry env='staging': (_core-upgrade-world-id-registry env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.worldIDRegistry.proxy' "$deploy")
    impl=$(jq -r '.worldIDRegistry.implementation' "$deploy")
    echo "Upgrading WorldIDRegistry $proxy → $impl"
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Simulate upgrading CredentialSchemaIssuerRegistry proxy.
# Example:  PRIVATE_KEY=0x... just _core-upgrade-issuer-registry staging
[private]
_core-upgrade-issuer-registry env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.credentialSchemaIssuerRegistry.proxy' "$deploy")
    impl=$(jq -r '.credentialSchemaIssuerRegistry.implementation' "$deploy")
    echo "Simulating: CredentialSchemaIssuerRegistry $proxy → $impl"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Upgrade CredentialSchemaIssuerRegistry proxy to the implementation in the deployment artifact.
# Example:  PRIVATE_KEY=0x... just core-upgrade-issuer-registry
#           PRIVATE_KEY=0x... just core-upgrade-issuer-registry production
[group('core · upgrade')]
[confirm("Upgrade CredentialSchemaIssuerRegistry on {{ env }}?")]
core-upgrade-issuer-registry env='staging': (_core-upgrade-issuer-registry env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.credentialSchemaIssuerRegistry.proxy' "$deploy")
    impl=$(jq -r '.credentialSchemaIssuerRegistry.implementation' "$deploy")
    echo "Upgrading CredentialSchemaIssuerRegistry $proxy → $impl"
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Simulate upgrading RpRegistry proxy.
# Example:  PRIVATE_KEY=0x... just _core-upgrade-rp-registry staging
[private]
_core-upgrade-rp-registry env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.rpRegistry.proxy' "$deploy")
    impl=$(jq -r '.rpRegistry.implementation' "$deploy")
    echo "Simulating: RpRegistry $proxy → $impl"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Upgrade RpRegistry proxy to the implementation in the deployment artifact.
# Example:  PRIVATE_KEY=0x... just core-upgrade-rp-registry
#           PRIVATE_KEY=0x... just core-upgrade-rp-registry production
[group('core · upgrade')]
[confirm("Upgrade RpRegistry on {{ env }}?")]
core-upgrade-rp-registry env='staging': (_core-upgrade-rp-registry env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.rpRegistry.proxy' "$deploy")
    impl=$(jq -r '.rpRegistry.implementation' "$deploy")
    echo "Upgrading RpRegistry $proxy → $impl"
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Simulate upgrading WorldIDVerifier proxy.
# Example:  PRIVATE_KEY=0x... just _core-upgrade-world-id-verifier staging
[private]
_core-upgrade-world-id-verifier env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.worldIDVerifier.proxy' "$deploy")
    impl=$(jq -r '.worldIDVerifier.implementation' "$deploy")
    echo "Simulating: WorldIDVerifier $proxy → $impl"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Upgrade WorldIDVerifier proxy to the implementation in the deployment artifact.
# Example:  PRIVATE_KEY=0x... just core-upgrade-world-id-verifier
#           PRIVATE_KEY=0x... just core-upgrade-world-id-verifier production
[group('core · upgrade')]
[confirm("Upgrade WorldIDVerifier on {{ env }}?")]
core-upgrade-world-id-verifier env='staging': (_core-upgrade-world-id-verifier env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.worldIDVerifier.proxy' "$deploy")
    impl=$(jq -r '.worldIDVerifier.implementation' "$deploy")
    echo "Upgrading WorldIDVerifier $proxy → $impl"
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "upgradeToAndCall(address,bytes)" "$impl" "0x"

# ─────────────────────────────────────────────────────────────────────────────
# core · ops
# ─────────────────────────────────────────────────────────────────────────────

# Pretty-print the current core deployment artifact.
# Example:  just core-status
#           just core-status production
[group('core · ops')]
core-status env='staging':
    @jq '.' "{{ CORE_DEPLOY_DIR }}/{{ env }}.json" 2>/dev/null \
        || echo "No core deployment found for '{{ env }}'"

# Simulate registering an issuer schema.
# Resolves CredentialSchemaIssuerRegistry proxy from deployments/core/{env}.json.
# Schema IDs: 1 (PoH), 11 (Face), 9303 (NFC), 9310 (MNC)
# Example:
#   PRIVATE_KEY=0x... just _core-issuer-register 1 115792... 99234... 0xSigner
#   PRIVATE_KEY=0x... just _core-issuer-register 9303 <x> <y> 0xSigner production
[private]
_core-issuer-register id pubkey_x pubkey_y signer env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.credentialSchemaIssuerRegistry.proxy' "$deploy")
    echo "Simulating register({{ id }}) on $proxy"
    echo "  pubkey:  ({{ pubkey_x }}, {{ pubkey_y }})"
    echo "  signer:  {{ signer }}"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "register(uint64,(uint256,uint256),address)(uint256)" \
        "{{ id }}" "({{ pubkey_x }},{{ pubkey_y }})" "{{ signer }}"

# Register an issuer schema in CredentialSchemaIssuerRegistry.
# Dry-runs first; prompts for confirmation before broadcasting.
# Schema IDs: 1 (PoH), 11 (Face), 9303 (NFC), 9310 (MNC)
# Example:
#   PRIVATE_KEY=0x... just core-issuer-register 1 115792... 99234... 0xSigner
#   PRIVATE_KEY=0x... just core-issuer-register 9303 <x> <y> 0xSigner production
[group('core · ops')]
[confirm("Register issuer schema id={{ id }} on {{ env }}?")]
core-issuer-register id pubkey_x pubkey_y signer env='staging': (_core-issuer-register id pubkey_x pubkey_y signer env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.credentialSchemaIssuerRegistry.proxy' "$deploy")
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "register(uint64,(uint256,uint256),address)" \
        "{{ id }}" "({{ pubkey_x }},{{ pubkey_y }})" "{{ signer }}"

# ── core · transfer-ownership ────────────────────────────────────────────────

# Simulate transferring WorldIDRegistry ownership (Ownable2Step: new owner must call acceptOwnership).
# Example:  PRIVATE_KEY=0x... just _core-transfer-ownership-world-id-registry 0xNewOwner
[private]
_core-transfer-ownership-world-id-registry new_owner env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.worldIDRegistry.proxy' "$deploy")
    echo "Simulating transferOwnership of WorldIDRegistry ($proxy) → {{ new_owner }}"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "transferOwnership(address)" "{{ new_owner }}"

# Transfer WorldIDRegistry ownership (new owner must call acceptOwnership).
# Example:  PRIVATE_KEY=0x... just core-transfer-ownership-world-id-registry 0xNewOwner
[group('core · ops')]
[confirm("Transfer WorldIDRegistry ownership to {{ new_owner }} on {{ env }}?")]
core-transfer-ownership-world-id-registry new_owner env='staging': (_core-transfer-ownership-world-id-registry new_owner env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.worldIDRegistry.proxy' "$deploy")
    echo "Transferring WorldIDRegistry ($proxy) ownership → {{ new_owner }}"
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "transferOwnership(address)" "{{ new_owner }}"
    echo "Done. New owner must call acceptOwnership()."

# Simulate transferring CredentialSchemaIssuerRegistry ownership.
# Example:  PRIVATE_KEY=0x... just _core-transfer-ownership-issuer-registry 0xNewOwner
[private]
_core-transfer-ownership-issuer-registry new_owner env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.credentialSchemaIssuerRegistry.proxy' "$deploy")
    echo "Simulating transferOwnership of CredentialSchemaIssuerRegistry ($proxy) → {{ new_owner }}"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "transferOwnership(address)" "{{ new_owner }}"

# Transfer CredentialSchemaIssuerRegistry ownership (new owner must call acceptOwnership).
# Example:  PRIVATE_KEY=0x... just core-transfer-ownership-issuer-registry 0xNewOwner
[group('core · ops')]
[confirm("Transfer CredentialSchemaIssuerRegistry ownership to {{ new_owner }} on {{ env }}?")]
core-transfer-ownership-issuer-registry new_owner env='staging': (_core-transfer-ownership-issuer-registry new_owner env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.credentialSchemaIssuerRegistry.proxy' "$deploy")
    echo "Transferring CredentialSchemaIssuerRegistry ($proxy) ownership → {{ new_owner }}"
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "transferOwnership(address)" "{{ new_owner }}"
    echo "Done. New owner must call acceptOwnership()."

# Simulate transferring RpRegistry ownership.
# Example:  PRIVATE_KEY=0x... just _core-transfer-ownership-rp-registry 0xNewOwner
[private]
_core-transfer-ownership-rp-registry new_owner env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.rpRegistry.proxy' "$deploy")
    echo "Simulating transferOwnership of RpRegistry ($proxy) → {{ new_owner }}"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "transferOwnership(address)" "{{ new_owner }}"

# Transfer RpRegistry ownership (new owner must call acceptOwnership).
# Example:  PRIVATE_KEY=0x... just core-transfer-ownership-rp-registry 0xNewOwner
[group('core · ops')]
[confirm("Transfer RpRegistry ownership to {{ new_owner }} on {{ env }}?")]
core-transfer-ownership-rp-registry new_owner env='staging': (_core-transfer-ownership-rp-registry new_owner env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.rpRegistry.proxy' "$deploy")
    echo "Transferring RpRegistry ($proxy) ownership → {{ new_owner }}"
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "transferOwnership(address)" "{{ new_owner }}"
    echo "Done. New owner must call acceptOwnership()."

# Simulate transferring WorldIDVerifier ownership.
# Example:  PRIVATE_KEY=0x... just _core-transfer-ownership-world-id-verifier 0xNewOwner
[private]
_core-transfer-ownership-world-id-verifier new_owner env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.worldIDVerifier.proxy' "$deploy")
    echo "Simulating transferOwnership of WorldIDVerifier ($proxy) → {{ new_owner }}"
    just _cast-dry-run "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "transferOwnership(address)" "{{ new_owner }}"

# Transfer WorldIDVerifier ownership (new owner must call acceptOwnership).
# Example:  PRIVATE_KEY=0x... just core-transfer-ownership-world-id-verifier 0xNewOwner
[group('core · ops')]
[confirm("Transfer WorldIDVerifier ownership to {{ new_owner }} on {{ env }}?")]
core-transfer-ownership-world-id-verifier new_owner env='staging': (_core-transfer-ownership-world-id-verifier new_owner env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ CORE_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.worldIDVerifier.proxy' "$deploy")
    echo "Transferring WorldIDVerifier ($proxy) ownership → {{ new_owner }}"
    just _cast-send "{{ WORLDCHAIN_RPC }}" "$proxy" \
        "transferOwnership(address)" "{{ new_owner }}"
    echo "Done. New owner must call acceptOwnership()."

# ─────────────────────────────────────────────────────────────────────────────
# crosschain · deploy
# ─────────────────────────────────────────────────────────────────────────────

# Simulate crosschain bridge deployment across all configured chains (no broadcast).
# Example:
#   PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just _crosschain-deploy-dry-run
#   PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just _crosschain-deploy-dry-run production
[private]
_crosschain-deploy-dry-run env='staging':
    cd {{ CONTRACTS_DIR }} && forge script {{ XC_SCRIPT }} \
        --sig "run(string)" "{{ env }}" \
        --private-key "$PRIVATE_KEY" \
        --multi

# Deploy crosschain bridge contracts (simulates first, then broadcasts).
# Filter chains with DEPLOY_CHAINS=ethereum,base.
# Example:
#   PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-deploy
#   DEPLOY_CHAINS=ethereum,base PRIVATE_KEY=0x... just crosschain-deploy staging
[group('crosschain · deploy')]
[confirm("Deploy crosschain bridge to {{ env }}?")]
crosschain-deploy env='staging': (_crosschain-deploy-dry-run env)
    cd {{ CONTRACTS_DIR }} && forge script {{ XC_SCRIPT }} \
        --sig "run(string)" "{{ env }}" \
        --private-key "$PRIVATE_KEY" \
        --multi \
        --broadcast

# ─────────────────────────────────────────────────────────────────────────────
# crosschain · upgrade
# ─────────────────────────────────────────────────────────────────────────────

# Resolve the RPC URL for a crosschain chain from its config.
# Priority: ALCHEMY_API_KEY + alchemySlug > config.rpc > public alchemySlug endpoint
[private]
_xc-rpc chain env:
    #!/usr/bin/env bash
    cfg="{{ XC_CFG_DIR }}/{{ env }}.json"
    if [ -n "${ALCHEMY_API_KEY:-}" ]; then
        slug=$(jq -r '.{{ chain }}.alchemySlug // empty' "$cfg")
        [ -n "$slug" ] && echo "https://${slug}.g.alchemy.com/v2/${ALCHEMY_API_KEY}" && exit 0
    fi
    rpc=$(jq -r '.{{ chain }}.rpc // empty' "$cfg")
    [ -n "$rpc" ] && echo "$rpc" && exit 0
    echo "https://$(jq -r '.{{ chain }}.alchemySlug' "$cfg").g.alchemy.com/public"

# Simulate upgrading the WorldIDSource proxy on World Chain.
# Example:  PRIVATE_KEY=0x... just _crosschain-upgrade-world-id-source worldchain
[private]
_crosschain-upgrade-world-id-source chain env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.{{ chain }}.worldIDSource.proxy // empty' "$deploy")
    impl=$(jq -r '.{{ chain }}.worldIDSource.implementation // empty' "$deploy")
    [ -n "$proxy" ] || { echo "error: worldIDSource not found for {{ chain }}"; exit 1; }
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Simulating: {{ chain }}/WorldIDSource $proxy → $impl"
    just _cast-dry-run "$rpc" "$proxy" "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Upgrade WorldIDSource proxy to the implementation in the deployment artifact.
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-upgrade-world-id-source worldchain
[group('crosschain · upgrade')]
[confirm("Upgrade WorldIDSource on {{ chain }}/{{ env }}?")]
crosschain-upgrade-world-id-source chain env='staging': (_crosschain-upgrade-world-id-source chain env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.{{ chain }}.worldIDSource.proxy' "$deploy")
    impl=$(jq -r '.{{ chain }}.worldIDSource.implementation' "$deploy")
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Upgrading {{ chain }}/WorldIDSource $proxy → $impl"
    just _cast-send "$rpc" "$proxy" "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Simulate upgrading the WorldIDSatellite proxy on a destination chain.
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just _crosschain-upgrade-world-id-satellite ethereum
[private]
_crosschain-upgrade-world-id-satellite chain env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy // empty' "$deploy")
    impl=$(jq -r '.{{ chain }}.worldIDSatellite.implementation // empty' "$deploy")
    [ -n "$proxy" ] || { echo "error: worldIDSatellite not found for {{ chain }}"; exit 1; }
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Simulating: {{ chain }}/WorldIDSatellite $proxy → $impl"
    just _cast-dry-run "$rpc" "$proxy" "upgradeToAndCall(address,bytes)" "$impl" "0x"

# Upgrade WorldIDSatellite proxy to the implementation in the deployment artifact.
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-upgrade-world-id-satellite ethereum
#           PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-upgrade-world-id-satellite base production
[group('crosschain · upgrade')]
[confirm("Upgrade WorldIDSatellite on {{ chain }}/{{ env }}?")]
crosschain-upgrade-world-id-satellite chain env='staging': (_crosschain-upgrade-world-id-satellite chain env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy' "$deploy")
    impl=$(jq -r '.{{ chain }}.worldIDSatellite.implementation' "$deploy")
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Upgrading {{ chain }}/WorldIDSatellite $proxy → $impl"
    just _cast-send "$rpc" "$proxy" "upgradeToAndCall(address,bytes)" "$impl" "0x"

# ─────────────────────────────────────────────────────────────────────────────
# crosschain · ops
# ─────────────────────────────────────────────────────────────────────────────

# Pretty-print the current crosschain deployment artifact.
# Example:  just crosschain-status
#           just crosschain-status production
[group('crosschain · ops')]
crosschain-status env='staging':
    @jq '.' "{{ XC_DEPLOY_DIR }}/{{ env }}.json" 2>/dev/null \
        || echo "No crosschain deployment found for '{{ env }}'"

# Simulate authorizing a gateway on a WorldIDSatellite.
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just _crosschain-gateway-add ethereum 0xGateway
[private]
_crosschain-gateway-add chain gateway env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy // empty' "$deploy")
    [ -n "$proxy" ] || { echo "error: no worldIDSatellite for {{ chain }}"; exit 1; }
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Simulating addGateway({{ gateway }}) on {{ chain }} satellite $proxy"
    just _cast-dry-run "$rpc" "$proxy" "addGateway(address)" "{{ gateway }}"

# Authorize a gateway on a WorldIDSatellite.
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-gateway-add ethereum 0xGateway
#           PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-gateway-add base 0xGateway production
[group('crosschain · ops')]
[confirm("Add gateway {{ gateway }} on {{ chain }}/{{ env }}?")]
crosschain-gateway-add chain gateway env='staging': (_crosschain-gateway-add chain gateway env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy' "$deploy")
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Adding gateway {{ gateway }} on {{ chain }} satellite $proxy"
    just _cast-send "$rpc" "$proxy" "addGateway(address)" "{{ gateway }}"

# Simulate revoking a gateway from a WorldIDSatellite.
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just _crosschain-gateway-remove ethereum 0xGateway
[private]
_crosschain-gateway-remove chain gateway env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy // empty' "$deploy")
    [ -n "$proxy" ] || { echo "error: no worldIDSatellite for {{ chain }}"; exit 1; }
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Simulating removeGateway({{ gateway }}) on {{ chain }} satellite $proxy"
    just _cast-dry-run "$rpc" "$proxy" "removeGateway(address)" "{{ gateway }}"

# Revoke a gateway from a WorldIDSatellite.
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-gateway-remove ethereum 0xGateway
[group('crosschain · ops')]
[confirm("Remove gateway {{ gateway }} from {{ chain }}/{{ env }}?")]
crosschain-gateway-remove chain gateway env='staging': (_crosschain-gateway-remove chain gateway env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy' "$deploy")
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Removing gateway {{ gateway }} from {{ chain }} satellite $proxy"
    just _cast-send "$rpc" "$proxy" "removeGateway(address)" "{{ gateway }}"

# ── crosschain · transfer-ownership ─────────────────────────────────────────

# Simulate transferring WorldIDSource ownership.
# Example:  PRIVATE_KEY=0x... just _crosschain-transfer-ownership-world-id-source worldchain 0xNewOwner
[private]
_crosschain-transfer-ownership-world-id-source chain new_owner env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.{{ chain }}.worldIDSource.proxy // empty' "$deploy")
    [ -n "$proxy" ] || { echo "error: worldIDSource not found for {{ chain }}"; exit 1; }
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Simulating transferOwnership of {{ chain }}/WorldIDSource ($proxy) → {{ new_owner }}"
    just _cast-dry-run "$rpc" "$proxy" "transferOwnership(address)" "{{ new_owner }}"

# Transfer WorldIDSource ownership (new owner must call acceptOwnership).
# Example:  PRIVATE_KEY=0x... just crosschain-transfer-ownership-world-id-source worldchain 0xNewOwner
[group('crosschain · ops')]
[confirm("Transfer WorldIDSource ownership on {{ chain }}/{{ env }} to {{ new_owner }}?")]
crosschain-transfer-ownership-world-id-source chain new_owner env='staging': (_crosschain-transfer-ownership-world-id-source chain new_owner env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.{{ chain }}.worldIDSource.proxy' "$deploy")
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Transferring {{ chain }}/WorldIDSource ($proxy) → {{ new_owner }}"
    just _cast-send "$rpc" "$proxy" "transferOwnership(address)" "{{ new_owner }}"
    echo "Done. New owner must call acceptOwnership()."

# Simulate transferring WorldIDSatellite ownership.
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just _crosschain-transfer-ownership-world-id-satellite ethereum 0xNewOwner
[private]
_crosschain-transfer-ownership-world-id-satellite chain new_owner env='staging':
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    [ -f "$deploy" ] || { echo "error: no deployment at $deploy"; exit 1; }
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy // empty' "$deploy")
    [ -n "$proxy" ] || { echo "error: worldIDSatellite not found for {{ chain }}"; exit 1; }
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Simulating transferOwnership of {{ chain }}/WorldIDSatellite ($proxy) → {{ new_owner }}"
    just _cast-dry-run "$rpc" "$proxy" "transferOwnership(address)" "{{ new_owner }}"

# Transfer WorldIDSatellite ownership (new owner must call acceptOwnership).
# Example:  PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-transfer-ownership-world-id-satellite ethereum 0xNewOwner
#           PRIVATE_KEY=0x... ALCHEMY_API_KEY=... just crosschain-transfer-ownership-world-id-satellite base 0xNewOwner production
[group('crosschain · ops')]
[confirm("Transfer WorldIDSatellite ownership on {{ chain }}/{{ env }} to {{ new_owner }}?")]
crosschain-transfer-ownership-world-id-satellite chain new_owner env='staging': (_crosschain-transfer-ownership-world-id-satellite chain new_owner env)
    #!/usr/bin/env bash
    set -euo pipefail
    deploy="{{ XC_DEPLOY_DIR }}/{{ env }}.json"
    proxy=$(jq -r '.{{ chain }}.worldIDSatellite.proxy' "$deploy")
    rpc=$(just _xc-rpc "{{ chain }}" "{{ env }}")
    echo "Transferring {{ chain }}/WorldIDSatellite ($proxy) → {{ new_owner }}"
    just _cast-send "$rpc" "$proxy" "transferOwnership(address)" "{{ new_owner }}"
    echo "Done. New owner must call acceptOwnership()."
