export PRIVATE_KEY=$(world-id-deployer-prod)

dry_run() {
  local env=${1:?usage: dry_run <environment>}
  forge script --sig "run(string)" --rpc-url $WORLDCHAIN_PROVIDER --private-key $PRIVATE_KEY script/core/Deploy.s.sol:Deploy "$env"
}

deploy() {
  local env=${1:?usage: deploy <environment>}
  forge script --sig "run(string)" --rpc-url $WORLDCHAIN_PROVIDER --verify --verifier-api-key $ETHERSCAN_API_KEY --verifier-url $ETHERSCAN_API_URL --broadcast --private-key $PRIVATE_KEY script/core/Deploy.s.sol:Deploy "$env"
}
