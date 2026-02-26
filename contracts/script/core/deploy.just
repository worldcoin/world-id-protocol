# World ID core contract deployment.
#
# Usage (from contracts/):
#   just --justfile script/core/deploy.just core-dry-run staging
#   just --justfile script/core/deploy.just core-deploy staging
#
# Required env vars:
#   PRIVATE_KEY                              Deployer private key (funded on target chain)
#   VERIFIER_API_KEY                         Block explorer API key
#
# Optional env vars:
#   WORLDCHAIN_PROVIDER                      RPC endpoint (default: World Chain mainnet public RPC)
#   VERIFIER_URL                             Verifier API endpoint (default: Worldscan etherscan v2)
#   SALT_VERIFIER                            CREATE2 salt for Verifier
#   SALT_WORLD_ID_REGISTRY                   CREATE2 salt for WorldIDRegistry proxy
#   SALT_CREDENTIAL_SCHEMA_ISSUER_REGISTRY   CREATE2 salt for CredentialSchemaIssuerRegistry proxy
#   SALT_RP_REGISTRY                         CREATE2 salt for RpRegistry proxy
#   SALT_WORLD_ID_VERIFIER                   CREATE2 salt for WorldIDVerifier proxy
#   (salts fall back to values in script/core/config/<env>.json when not set)

SCRIPT        := "script/core/Deploy.s.sol:Deploy"
RPC_URL       := env_var_or_default("WORLDCHAIN_PROVIDER", "https://worldchain-mainnet.g.alchemy.com/public")
VERIFIER_URL  := env_var_or_default("VERIFIER_URL", "https://api.etherscan.io/v2/api?chainid=480")

# Simulate core contract deployment without broadcasting.
[group('deploy')]
core-dry-run env:
    cd {{CONTRACTS_DIR}} && GIT_COMMIT=$(git -C {{ROOT}} rev-parse HEAD) forge script {{SCRIPT}} \
        --sig "run(string)" "{{env}}" \
        --private-key "$PRIVATE_KEY" \
        --rpc-url "{{RPC_URL}}"

# Simulate then broadcast core contract deployment with verification.
[group('deploy')]
core-deploy env: (core-dry-run env)
    cd {{CONTRACTS_DIR}} && GIT_COMMIT=$(git -C {{ROOT}} rev-parse HEAD) forge script {{SCRIPT}} \
        --sig "run(string)" "{{env}}" \
        --private-key "$PRIVATE_KEY" \
        --rpc-url "{{RPC_URL}}" \
        --chain 480 \
        --broadcast \
        --verify \
        --verifier etherscan \
        --verifier-url "{{VERIFIER_URL}}" \
        --etherscan-api-key "$VERIFIER_API_KEY"
