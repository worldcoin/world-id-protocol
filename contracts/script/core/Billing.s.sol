// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {FixedPriceSource} from "../../src/core/FixedPriceSource.sol";
import {WorldIDBilling} from "../../src/core/WorldIDBilling.sol";

/// @title DeployBilling
/// @notice Deploys the WIP-107 Billing Contract for an environment whose core contracts are deployed.
/// @dev Reads `script/core/config/billing-<env>.json` and the `WorldIDVerifier` and `RpRegistry` proxies of
///  `deployments/core/<env>.json`, and writes `deployments/core/billing-<env>.json` when it broadcasts. The broadcaster must be the
///  config's `deployer`: it initializes the proxy, so it becomes the owner of the Billing Contract and of the
///  price source. No RP is billed; the owner adds them with `setBilledRp`.
///
///  Usage, signing with AWS KMS:
///  AWS_KMS_KEY_ID=<key id> forge script script/core/Billing.s.sol:DeployBilling --sig "run(string)" staging \
///      --rpc-url $RPC_URL --aws --broadcast
contract DeployBilling is Script {
    struct Config {
        address deployer;
        /// @dev The zero address deploys a freely mintable `ERC20Mock` as the fee token.
        address feeToken;
        address feeRecipient;
        /// @dev The rate `FixedPriceSource` reports, USD per fee token scaled by 1e18.
        uint256 usdPerWld;
        uint256 pricePerWorldID;
        uint64 maxPriceAge;
        uint64 maxRequestAge;
        uint64 maxRequestLifetime;
    }

    address public worldIDVerifier;
    address public rpRegistry;
    address public feeToken;
    FixedPriceSource public priceSource;
    WorldIDBilling public billingImplementation;
    WorldIDBilling public billing;
    uint256 public startBlock;

    function run(string calldata env) public {
        Config memory config = _loadConfig(env);
        string memory core = vm.readFile(string.concat("deployments/core/", env, ".json"));
        worldIDVerifier = vm.parseJsonAddress(core, ".worldIDVerifier.proxy");
        rpRegistry = vm.parseJsonAddress(core, ".rpRegistry.proxy");
        require(msg.sender == config.deployer, "broadcaster is not the configured deployer");

        startBlock = block.number;
        vm.startBroadcast();
        feeToken = config.feeToken == address(0) ? address(new ERC20Mock()) : config.feeToken;
        priceSource = new FixedPriceSource(config.deployer);
        priceSource.setPrice(config.usdPerWld);
        billingImplementation = new WorldIDBilling(worldIDVerifier, rpRegistry);
        bytes memory initData = abi.encodeCall(
            WorldIDBilling.initialize,
            (
                address(priceSource),
                feeToken,
                config.feeRecipient,
                config.pricePerWorldID,
                config.maxPriceAge,
                config.maxRequestAge,
                config.maxRequestLifetime
            )
        );
        billing = WorldIDBilling(address(new ERC1967Proxy(address(billingImplementation), initData)));
        vm.stopBroadcast();

        _check(config);
        // A simulation's addresses are never deployed, so only a broadcast is recorded.
        if (vm.isContext(VmSafe.ForgeContext.ScriptBroadcast) || vm.isContext(VmSafe.ForgeContext.ScriptResume)) {
            _writeDeployment(env, config);
        }
    }

    function _loadConfig(string memory env) internal view returns (Config memory config) {
        string memory json = vm.readFile(string.concat("script/core/config/billing-", env, ".json"));
        config.deployer = vm.parseJsonAddress(json, ".deployer");
        config.feeToken = vm.parseJsonAddress(json, ".feeToken");
        config.feeRecipient = vm.parseJsonAddress(json, ".feeRecipient");
        config.usdPerWld = vm.parseJsonUint(json, ".usdPerWld");
        config.pricePerWorldID = vm.parseJsonUint(json, ".pricePerWorldID");
        config.maxPriceAge = SafeCast.toUint64(vm.parseJsonUint(json, ".maxPriceAge"));
        config.maxRequestAge = SafeCast.toUint64(vm.parseJsonUint(json, ".maxRequestAge"));
        config.maxRequestLifetime = SafeCast.toUint64(vm.parseJsonUint(json, ".maxRequestLifetime"));
    }

    /// @dev Reads the deployed state back, so a wrong deployment fails before it is recorded.
    function _check(Config memory config) internal view {
        require(billing.owner() == config.deployer, "billing owner");
        require(priceSource.owner() == config.deployer, "price source owner");
        require(billing.priceSource() == address(priceSource), "price source");
        require(billing.getFeeToken() == feeToken, "fee token");
        require(billing.getFeeRecipient() == config.feeRecipient, "fee recipient");
        require(billing.pricePerWorldID() == config.pricePerWorldID, "price per World ID");
        require(billing.maxPriceAge() == config.maxPriceAge, "max price age");
        require(billing.maxRequestAge() == config.maxRequestAge, "max request age");
        require(billing.maxRequestLifetime() == config.maxRequestLifetime, "max request lifetime");
        require(!billing.paused(), "paused");
        (, int256 answer,,,) = priceSource.latestRoundData();
        require(answer == SafeCast.toInt256(config.usdPerWld), "WLD/USD rate");

        console2.log("WorldIDBilling proxy:", address(billing));
        console2.log("WorldIDBilling implementation:", address(billingImplementation));
        console2.log("FixedPriceSource:", address(priceSource));
        console2.log("Fee token:", feeToken);
        console2.log("Start block:", startBlock);
    }

    function _writeDeployment(string memory env, Config memory config) internal {
        string memory proxy = "worldIDBilling";
        vm.serializeAddress(proxy, "implementation", address(billingImplementation));
        string memory proxyJson = vm.serializeAddress(proxy, "proxy", address(billing));

        string memory root = "root";
        vm.serializeUint(root, "chainId", block.chainid);
        vm.serializeAddress(root, "deployer", config.deployer);
        // A lower bound of the deployment block, for the indexer's `BILLING_START_BLOCK`.
        vm.serializeUint(root, "startBlock", startBlock);
        vm.serializeUint(root, "timestamp", block.timestamp);
        vm.serializeString(root, "commitSha", vm.envOr("GIT_COMMIT", string("")));
        vm.serializeAddress(root, "worldIDVerifier", worldIDVerifier);
        vm.serializeAddress(root, "rpRegistry", rpRegistry);
        vm.serializeAddress(root, "feeToken", feeToken);
        vm.serializeAddress(root, "priceSource", address(priceSource));
        string memory json = vm.serializeString(root, "worldIDBilling", proxyJson);

        string memory path = string.concat("deployments/core/billing-", env, ".json");
        vm.writeJson(json, path);
        console2.log("Deployment written to", path);
    }
}
