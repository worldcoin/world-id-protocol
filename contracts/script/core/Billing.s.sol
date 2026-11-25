// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {FixedPriceSource} from "../../src/core/FixedPriceSource.sol";
import {WorldIDBilling} from "../../src/core/WorldIDBilling.sol";
import {IChainlinkAggregator} from "../../src/core/interfaces/IChainlinkAggregator.sol";
import {IWorldIDBilling} from "../../src/core/interfaces/IWorldIDBilling.sol";

/// @notice Reads `script/core/config/billing-<env>.json`, shared by the Billing Contract scripts.
abstract contract BillingScript is Script {
    struct Config {
        address deployer;
        /// @dev The zero address deploys a freely mintable `ERC20Mock` as the fee token.
        address feeToken;
        address feeRecipient;
        /// @dev A Chainlink-compatible WLD/USD feed with 18 decimals. The zero address deploys a `FixedPriceSource`
        ///  that reports `usdPerWld`.
        address priceSource;
        /// @dev USD per fee token scaled by 1e18, read only when `priceSource` is the zero address.
        uint256 usdPerWld;
        uint256 pricePerWorldID;
        uint64 maxPriceAge;
        uint64 maxRequestAge;
        uint64 maxRequestLifetime;
    }

    function _loadConfig(string memory env) internal view returns (Config memory config) {
        string memory json = vm.readFile(string.concat("script/core/config/billing-", env, ".json"));
        config.deployer = vm.parseJsonAddress(json, ".deployer");
        config.feeToken = vm.parseJsonAddress(json, ".feeToken");
        config.feeRecipient = vm.parseJsonAddress(json, ".feeRecipient");
        config.priceSource = vm.parseJsonAddress(json, ".priceSource");
        if (config.priceSource == address(0)) config.usdPerWld = vm.parseJsonUint(json, ".usdPerWld");
        config.pricePerWorldID = vm.parseJsonUint(json, ".pricePerWorldID");
        config.maxPriceAge = SafeCast.toUint64(vm.parseJsonUint(json, ".maxPriceAge"));
        config.maxRequestAge = SafeCast.toUint64(vm.parseJsonUint(json, ".maxRequestAge"));
        config.maxRequestLifetime = SafeCast.toUint64(vm.parseJsonUint(json, ".maxRequestLifetime"));
    }

    function _deploymentPath(string memory env) internal pure returns (string memory) {
        return string.concat("deployments/core/billing-", env, ".json");
    }

    function _isBroadcast() internal view returns (bool) {
        return vm.isContext(VmSafe.ForgeContext.ScriptBroadcast) || vm.isContext(VmSafe.ForgeContext.ScriptResume);
    }

    /// @dev Quotes one seat for the whole next period, so a price source the Billing Contract rejects fails the script.
    function _logSeatQuote(WorldIDBilling billing) internal view {
        (, uint64 nextPeriodStart) = billing.getBillingPeriod(uint64(block.timestamp));
        IWorldIDBilling.BillingContext memory scope = IWorldIDBilling.BillingContext({
            chainId: block.chainid, billingContract: address(billing), rpId: 0, periodStart: nextPeriodStart
        });
        uint256 feeTokenPerSeat = billing.quotePurchase(scope, 1);
        (, int256 usdPerFeeToken,,,) = IChainlinkAggregator(billing.priceSource()).latestRoundData();
        console2.log("USD per fee token (1e18):", uint256(usdPerFeeToken));
        console2.log("Fee token per seat, next period (1e18):", feeTokenPerSeat);
    }
}

/// @title DeployBilling
/// @notice Deploys the WIP-107 Billing Contract for an environment whose core contracts are deployed.
/// @dev Reads `script/core/config/billing-<env>.json` and the `WorldIDVerifier` and `RpRegistry` proxies of
///  `deployments/core/<env>.json`, and writes `deployments/core/billing-<env>.json` when it broadcasts. The broadcaster must be the
///  config's `deployer`: it initializes the proxy, so it becomes the owner of the Billing Contract and of a deployed
///  `FixedPriceSource`. No RP is billed; the owner adds them with `setBilledRp`.
///
///  Usage, signing with AWS KMS:
///  AWS_KMS_KEY_ID=<key id> forge script script/core/Billing.s.sol:DeployBilling --sig "run(string)" staging \
///      --rpc-url $RPC_URL --aws --broadcast
contract DeployBilling is BillingScript {
    address public worldIDVerifier;
    address public rpRegistry;
    address public feeToken;
    address public priceSource;
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
        priceSource = config.priceSource == address(0) ? _deployFixedPriceSource(config) : config.priceSource;
        billingImplementation = new WorldIDBilling(worldIDVerifier, rpRegistry);
        bytes memory initData = abi.encodeCall(
            WorldIDBilling.initialize,
            (
                priceSource,
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
        if (_isBroadcast()) _writeDeployment(env, config);
    }

    function _deployFixedPriceSource(Config memory config) internal returns (address) {
        FixedPriceSource fixedPriceSource = new FixedPriceSource(config.deployer);
        fixedPriceSource.setPrice(config.usdPerWld);
        return address(fixedPriceSource);
    }

    /// @dev Reads the deployed state back, so a wrong deployment fails before it is recorded.
    function _check(Config memory config) internal view {
        require(billing.owner() == config.deployer, "billing owner");
        require(billing.priceSource() == priceSource, "price source");
        require(billing.getFeeToken() == feeToken, "fee token");
        require(billing.getFeeRecipient() == config.feeRecipient, "fee recipient");
        require(billing.pricePerWorldID() == config.pricePerWorldID, "price per World ID");
        require(billing.maxPriceAge() == config.maxPriceAge, "max price age");
        require(billing.maxRequestAge() == config.maxRequestAge, "max request age");
        require(billing.maxRequestLifetime() == config.maxRequestLifetime, "max request lifetime");
        require(!billing.paused(), "paused");
        if (config.priceSource == address(0)) {
            FixedPriceSource fixedPriceSource = FixedPriceSource(priceSource);
            require(fixedPriceSource.owner() == config.deployer, "price source owner");
            (, int256 answer,,,) = fixedPriceSource.latestRoundData();
            require(answer == SafeCast.toInt256(config.usdPerWld), "WLD/USD rate");
        }
        _logSeatQuote(billing);

        console2.log("WorldIDBilling proxy:", address(billing));
        console2.log("WorldIDBilling implementation:", address(billingImplementation));
        console2.log("Price source:", priceSource);
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
        vm.serializeAddress(root, "priceSource", priceSource);
        string memory json = vm.serializeString(root, "worldIDBilling", proxyJson);

        string memory path = _deploymentPath(env);
        vm.writeJson(json, path);
        console2.log("Deployment written to", path);
    }
}

/// @title ConfigureBilling
/// @notice Points a deployed Billing Contract at the config's price source and fee token.
/// @dev Reads the proxy from `deployments/core/billing-<env>.json` and updates that file's `priceSource` and
///  `feeToken` when it broadcasts. The broadcaster must be the Billing Contract owner. A value that is already set is
///  skipped, so a rerun sends nothing. Capacity is counted in seats, so purchased capacity stays valid.
///
///  Usage, signing with AWS KMS:
///  AWS_KMS_KEY_ID=<key id> forge script script/core/Billing.s.sol:ConfigureBilling --sig "run(string)" staging \
///      --rpc-url $RPC_URL --aws --broadcast
contract ConfigureBilling is BillingScript {
    function run(string calldata env) public {
        Config memory config = _loadConfig(env);
        require(config.priceSource != address(0), "config has no price source");
        require(config.feeToken != address(0), "config has no fee token");
        string memory path = _deploymentPath(env);
        WorldIDBilling billing = WorldIDBilling(vm.parseJsonAddress(vm.readFile(path), ".worldIDBilling.proxy"));
        require(msg.sender == billing.owner(), "broadcaster is not the Billing Contract owner");

        address oldPriceSource = billing.priceSource();
        address oldFeeToken = billing.getFeeToken();
        console2.log("Previous price source:", oldPriceSource);
        console2.log("Previous fee token:", oldFeeToken);

        // The price source goes first, so the new fee token is never charged at the old source's rate.
        vm.startBroadcast();
        if (oldPriceSource != config.priceSource) billing.setPriceSource(config.priceSource);
        if (oldFeeToken != config.feeToken) billing.setFeeToken(config.feeToken);
        vm.stopBroadcast();

        require(billing.priceSource() == config.priceSource, "price source");
        require(billing.getFeeToken() == config.feeToken, "fee token");
        _logSeatQuote(billing);

        if (_isBroadcast()) {
            vm.writeJson(_jsonString(config.priceSource), path, ".priceSource");
            vm.writeJson(_jsonString(config.feeToken), path, ".feeToken");
            console2.log("Deployment updated at", path);
        }
    }

    function _jsonString(address value) internal pure returns (string memory) {
        return string.concat('"', vm.toString(value), '"');
    }
}
