// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {DateTimeLib} from "solady/utils/DateTimeLib.sol";
import {OprfKeyRegistry} from "oprf-key-registry/src/OprfKeyRegistry.sol";
import {BabyJubJub} from "oprf-key-registry/src/BabyJubJub.sol";
import {WorldIDBase} from "./abstract/WorldIDBase.sol";
import {IWorldIDVerifier} from "./interfaces/IWorldIDVerifier.sol";
import {IRpRegistry} from "./interfaces/IRpRegistry.sol";
import {IWorldIDBilling} from "./interfaces/IWorldIDBilling.sol";
import {IChainlinkAggregator} from "./interfaces/IChainlinkAggregator.sol";
import {IWIP101} from "./interfaces/IWIP101.sol";

/// @title WorldIDBilling
/// @author World Contributors
/// @notice Sells prorated monthly registration capacity in WLD with a 26-hour overlap (WIP-107).
/// @custom:security-contact security@toolsforhumanity.com
contract WorldIDBilling is WorldIDBase, PausableUpgradeable, ReentrancyGuardTransient, IWorldIDBilling {
    using SafeERC20 for IERC20;

    ////////////////////////////////////////////////////////////
    //                       Immutables                       //
    ////////////////////////////////////////////////////////////

    /// @notice Verifies registration Uniqueness Proofs.
    IWorldIDVerifier public immutable WORLD_ID_VERIFIER;

    /// @notice Resolves RP signers and OPRF key IDs.
    IRpRegistry public immutable RP_REGISTRY;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev Chainlink WLD/USD feed backed by verified Data Streams reports.
    IChainlinkAggregator internal _priceSource;

    /// @inheritdoc IWorldIDBilling
    uint256 public pricePerWorldID;

    /// @inheritdoc IWorldIDBilling
    uint64 public maxPriceAge;

    /// @inheritdoc IWorldIDBilling
    mapping(uint64 rpId => mapping(uint64 periodStart => Period)) public periods;

    /// @inheritdoc IWorldIDBilling
    mapping(uint256 billingNullifier => bool) public isRegistered;

    /// @inheritdoc IWorldIDBilling
    mapping(uint64 rpId => mapping(uint256 nonce => bool)) public usedNonces;

    /// @dev OPRF key pinned by the first registration for each RP and period.
    mapping(uint64 rpId => mapping(uint64 periodStart => PinnedOprfKey)) internal _pinnedOprfKeys;

    /// @inheritdoc IWorldIDBilling
    uint64 public maxRequestAge;

    /// @inheritdoc IWorldIDBilling
    uint64 public maxRequestLifetime;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "WorldIDBilling";
    string public constant EIP712_VERSION = "1.0";

    string public constant BILLING_ACTION_DOMAIN = "world-id-billing-v1";

    uint8 public constant AUTHORIZATION_VERSION = 0x01;

    uint256 public constant MAX_WIP101_DATA_LENGTH = 1024;

    uint8 internal constant PRICE_DECIMALS = 18;

    /// @notice Decimals of the WLD fee token; `setFeeToken` rejects tokens with other decimals.
    uint8 public constant TOKEN_DECIMALS = 18;

    uint256 internal constant TOKEN_UNIT = 10 ** TOKEN_DECIMALS;

    uint256 internal constant AOE_OFFSET = 12 hours;

    uint256 internal constant PERIOD_OVERLAP = 26 hours;

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @param worldIDVerifier `WorldIDVerifier` proxy that verifies registration proofs.
    /// @param rpRegistry `RpRegistry` proxy resolving RP signers and OPRF key IDs.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address worldIDVerifier, address rpRegistry) {
        if (worldIDVerifier == address(0)) revert ZeroAddress();
        if (rpRegistry == address(0)) revert ZeroAddress();
        WORLD_ID_VERIFIER = IWorldIDVerifier(worldIDVerifier);
        RP_REGISTRY = IRpRegistry(rpRegistry);
        _disableInitializers();
    }

    /**
     * @notice Initializes the billing proxy; the caller becomes the owner.
     * @param initialPriceSource Chainlink WLD/USD feed backed by verified Data Streams reports.
     * @param feeToken WLD ERC-20.
     * @param feeRecipient Protocol fee address.
     * @param initialPricePerWorldID USD per World ID per period, scaled by 1e18.
     * @param initialMaxPriceAge Maximum accepted price age in seconds.
     * @param initialMaxRequestAge Maximum accepted authorization age in seconds; must match the OPRF nodes.
     * @param initialMaxRequestLifetime Maximum accepted authorization lifetime in seconds; must match the OPRF nodes.
     */
    function initialize(
        address initialPriceSource,
        address feeToken,
        address feeRecipient,
        uint256 initialPricePerWorldID,
        uint64 initialMaxPriceAge,
        uint64 initialMaxRequestAge,
        uint64 initialMaxRequestLifetime
    ) public virtual initializer {
        if (initialPriceSource == address(0)) revert ZeroAddress();
        if (feeToken == address(0)) revert ZeroAddress();
        if (feeRecipient == address(0)) revert ZeroAddress();

        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, feeRecipient, feeToken, 0);
        __Pausable_init();

        if (IERC20Metadata(feeToken).decimals() != TOKEN_DECIMALS) revert InvalidTokenDecimals();
        if (initialPricePerWorldID == 0) revert InvalidPricePerWorldID();
        if (initialMaxPriceAge == 0) revert InvalidMaxPriceAge();

        _priceSource = IChainlinkAggregator(initialPriceSource);
        pricePerWorldID = initialPricePerWorldID;
        maxPriceAge = initialMaxPriceAge;
        emit PricePerWorldIDUpdated(0, initialPricePerWorldID);
        emit MaxPriceAgeUpdated(0, initialMaxPriceAge);
        _setRequestLimits(initialMaxRequestAge, initialMaxRequestLifetime);
    }

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDBilling
    function purchaseCapacity(BillingContext calldata scope, uint256 capacityAmount, uint256 maxWldAmount)
        external
        virtual
        onlyProxy
        nonReentrant
    {
        // Reverts for unknown or inactive RPs so payment cannot buy unusable capacity.
        RP_REGISTRY.getOprfKeyIdAndSigner(scope.rpId);
        uint256 wldPaid = quotePurchase(scope, capacityAmount);
        if (wldPaid > maxWldAmount) revert MaxWldAmountExceeded(wldPaid, maxWldAmount);

        periods[scope.rpId][scope.periodStart].capacity += capacityAmount;

        address recipient = _feeRecipient;
        uint256 balanceBefore = _feeToken.balanceOf(recipient);
        _feeToken.safeTransferFrom(msg.sender, recipient, wldPaid);
        uint256 received = _feeToken.balanceOf(recipient) - balanceBefore;
        if (received != wldPaid) revert FeeTransferMismatch(wldPaid, received);

        emit CapacityPurchased(scope.rpId, scope.periodStart, msg.sender, capacityAmount, wldPaid);
    }

    /// @inheritdoc IWorldIDBilling
    function register(
        BillingContext calldata scope,
        RegistrationAuthorization calldata authorization,
        uint64 issuerSchemaId,
        uint64 expiresAtMin,
        uint256 billingNullifier,
        uint256[5] calldata proof
    ) external virtual onlyProxy nonReentrant returns (bool success) {
        return _register(scope, authorization, issuerSchemaId, expiresAtMin, billingNullifier, proof);
    }

    /// @inheritdoc IWorldIDBilling
    function registerMany(BillingContext calldata scope, Registration[] calldata registrations)
        external
        virtual
        onlyProxy
        nonReentrant
        returns (bool[] memory successes)
    {
        successes = new bool[](registrations.length);
        for (uint256 i = 0; i < registrations.length; ++i) {
            Registration calldata registration = registrations[i];
            successes[i] = _register(
                scope,
                registration.authorization,
                registration.issuerSchemaId,
                registration.expiresAtMin,
                registration.billingNullifier,
                registration.proof
            );
        }
    }

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDBilling
    function quotePurchase(BillingContext calldata scope, uint256 capacityAmount)
        public
        view
        virtual
        onlyProxy
        returns (uint256 wldAmount)
    {
        _validateScope(scope);
        if (capacityAmount == 0) revert ZeroCapacityAmount();

        uint256 currentStart = _monthStart(block.timestamp);
        uint64 nextStart = _addMonths(currentStart, 1);
        if (scope.periodStart < currentStart || scope.periodStart > nextStart) revert PeriodOutsidePurchaseWindow();

        uint256 usdPerWld = _verifiedUsdPerWld();
        uint256 usdTotal = capacityAmount * pricePerWorldID;
        uint256 monthEnd = _addMonths(scope.periodStart, 1);
        uint256 duration = monthEnd - scope.periodStart;
        uint256 remaining = monthEnd - Math.max(block.timestamp, scope.periodStart);
        return Math.mulDiv(usdTotal, remaining * TOKEN_UNIT, duration * usdPerWld, Math.Rounding.Ceil);
    }

    /// @inheritdoc IWorldIDBilling
    function getBillingPeriod(uint64 timestamp) external pure virtual returns (uint64 periodStart, uint64 periodEnd) {
        periodStart = _monthStart(timestamp);
        periodEnd = _addMonths(periodStart, 1);
    }

    /// @inheritdoc IWorldIDBilling
    function getPinnedOprfKey(uint64 rpId, uint64 periodStart)
        external
        view
        virtual
        returns (uint160 oprfKeyId, uint256[2] memory oprfPublicKey)
    {
        PinnedOprfKey storage pinned = _pinnedOprfKeys[rpId][periodStart];
        return (pinned.oprfKeyId, [pinned.x, pinned.y]);
    }

    /// @inheritdoc IWorldIDBilling
    function getBillingAction(BillingContext calldata scope) public pure virtual returns (uint256) {
        // The shift reduces the hash into the field with a 0x00 uniqueness prefix.
        return uint256(
            keccak256(
            abi.encode(BILLING_ACTION_DOMAIN, scope.chainId, scope.billingContract, scope.rpId, scope.periodStart)
        )
        ) >> 8;
    }

    /// @inheritdoc IWorldIDBilling
    function setFeeToken(address newFeeToken)
        external
        virtual
        override(WorldIDBase, IWorldIDBilling)
        onlyOwner
        onlyProxy
    {
        if (newFeeToken == address(0)) revert ZeroAddress();
        if (IERC20Metadata(newFeeToken).decimals() != TOKEN_DECIMALS) revert InvalidTokenDecimals();
        address oldToken = address(_feeToken);
        _feeToken = IERC20(newFeeToken);
        emit FeeTokenUpdated(oldToken, newFeeToken);
    }

    /// @inheritdoc IWorldIDBilling
    function setPricePerWorldID(uint256 newPricePerWorldID) external virtual onlyOwner onlyProxy {
        if (newPricePerWorldID == 0) revert InvalidPricePerWorldID();
        emit PricePerWorldIDUpdated(pricePerWorldID, newPricePerWorldID);
        pricePerWorldID = newPricePerWorldID;
    }

    /// @inheritdoc IWorldIDBilling
    function setMaxPriceAge(uint64 newMaxPriceAge) external virtual onlyOwner onlyProxy {
        if (newMaxPriceAge == 0) revert InvalidMaxPriceAge();
        emit MaxPriceAgeUpdated(maxPriceAge, newMaxPriceAge);
        maxPriceAge = newMaxPriceAge;
    }

    /// @inheritdoc IWorldIDBilling
    function setPriceSource(address newPriceSource) external virtual onlyOwner onlyProxy {
        if (newPriceSource == address(0)) revert ZeroAddress();
        emit PriceSourceUpdated(address(_priceSource), newPriceSource);
        _priceSource = IChainlinkAggregator(newPriceSource);
    }

    /// @inheritdoc IWorldIDBilling
    function setRequestLimits(uint64 newMaxRequestAge, uint64 newMaxRequestLifetime)
        external
        virtual
        onlyOwner
        onlyProxy
    {
        _setRequestLimits(newMaxRequestAge, newMaxRequestLifetime);
    }

    /// @inheritdoc IWorldIDBilling
    function setPaused(bool isPaused) external virtual onlyOwner onlyProxy {
        if (isPaused) _pause();
        else _unpause();
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /// @dev Reads the feed and normalizes it to USD per WLD scaled by 1e18. `updatedAt` is the report's
    ///  observation time, not the submission time.
    function _register(
        BillingContext calldata scope,
        RegistrationAuthorization calldata authorization,
        uint64 issuerSchemaId,
        uint64 expiresAtMin,
        uint256 billingNullifier,
        uint256[5] calldata proof
    ) internal returns (bool) {
        _validateScope(scope);
        if (block.timestamp + PERIOD_OVERLAP < scope.periodStart || block.timestamp >= _addMonths(scope.periodStart, 1))
        {
            revert PeriodNotCurrent();
        }

        mapping(uint256 => bool) storage nonces = usedNonces[scope.rpId];
        if (nonces[authorization.nonce]) revert NonceAlreadyUsed();

        uint256 billingAction = getBillingAction(scope);
        (uint160 oprfKeyId, address signer) = RP_REGISTRY.getOprfKeyIdAndSigner(scope.rpId);
        if (authorization.oprfKeyId != oprfKeyId) revert OprfKeyMismatch();

        _verifyAuthorization(authorization, signer, billingAction);
        nonces[authorization.nonce] = true;
        _checkPinnedOprfKey(scope, oprfKeyId);

        // Uniqueness Proof with signal, genesis minimum and session set to zero (WIP-107 §4.3.1).
        WORLD_ID_VERIFIER.verifyProofAndSignals(
            billingNullifier,
            billingAction,
            scope.rpId,
            authorization.nonce,
            0,
            expiresAtMin,
            issuerSchemaId,
            0,
            0,
            proof
        );

        if (isRegistered[billingNullifier]) return false;

        // Duplicates above still succeed while paused; only new registrations stop.
        _requireNotPaused();
        Period storage period = periods[scope.rpId][scope.periodStart];
        if (period.registeredCount >= period.capacity) revert CapacityExhausted();

        period.registeredCount += 1;
        isRegistered[billingNullifier] = true;
        emit Registered(scope.rpId, scope.periodStart, billingNullifier);
        return true;
    }

    /// @dev Pins the RP's OPRF key on the period's first registration. Later registrations require the same key,
    ///  because `WORLD_ID_VERIFIER` checks proofs against the registry's current key.
    function _checkPinnedOprfKey(BillingContext calldata scope, uint160 oprfKeyId) internal {
        // `WORLD_ID_VERIFIER` reads the key at `uint160(rpId)`, so the pin must cover that key.
        if (oprfKeyId != uint160(scope.rpId)) revert OprfKeyMismatch();
        BabyJubJub.Affine memory key =
            OprfKeyRegistry(WORLD_ID_VERIFIER.getOprfKeyRegistry()).getOprfPublicKey(oprfKeyId);
        // (0, 0) is not on BabyJubJub, so it marks an unpinned period and is never a valid key.
        if (key.x == 0 && key.y == 0) revert OprfKeyMismatch();
        PinnedOprfKey storage pinned = _pinnedOprfKeys[scope.rpId][scope.periodStart];
        if (pinned.x == 0 && pinned.y == 0) {
            (pinned.oprfKeyId, pinned.x, pinned.y) = (oprfKeyId, key.x, key.y);
            emit OprfKeyPinned(scope.rpId, scope.periodStart, oprfKeyId);
        } else if (pinned.oprfKeyId != oprfKeyId || pinned.x != key.x || pinned.y != key.y) {
            revert PinnedOprfKeyChanged();
        }
    }

    function _setRequestLimits(uint64 newMaxRequestAge, uint64 newMaxRequestLifetime) internal {
        if (newMaxRequestAge == 0 || newMaxRequestLifetime == 0) revert InvalidRequestLimits();
        emit RequestLimitsUpdated(maxRequestAge, maxRequestLifetime, newMaxRequestAge, newMaxRequestLifetime);
        maxRequestAge = newMaxRequestAge;
        maxRequestLifetime = newMaxRequestLifetime;
    }

    function _verifiedUsdPerWld() internal view returns (uint256) {
        int256 answer;
        uint256 observedAt;
        uint8 feedDecimals;
        try _priceSource.latestRoundData() returns (uint80, int256 price, uint256, uint256 updatedAt, uint80) {
            (answer, observedAt) = (price, updatedAt);
        } catch {
            revert PriceUnavailable();
        }
        try _priceSource.decimals() returns (uint8 decimals) {
            feedDecimals = decimals;
        } catch {
            revert PriceUnavailable();
        }
        if (answer <= 0) revert InvalidPrice();
        if (observedAt > block.timestamp) revert PriceFromFuture(observedAt);
        if (block.timestamp - observedAt > maxPriceAge) revert StalePrice(observedAt);

        return feedDecimals <= PRICE_DECIMALS
            ? uint256(answer) * 10 ** (PRICE_DECIMALS - feedDecimals)
            : uint256(answer) / 10 ** (feedDecimals - PRICE_DECIMALS);
    }

    function _validateScope(BillingContext calldata scope) internal view {
        if (scope.chainId != block.chainid) revert InvalidChainId();
        if (scope.billingContract != address(this)) revert InvalidBillingContract();
        if (scope.periodStart != _monthStart(scope.periodStart)) revert NonCanonicalPeriodStart();
    }

    function _verifyAuthorization(
        RegistrationAuthorization calldata authorization,
        address signer,
        uint256 billingAction
    ) internal view {
        if (authorization.version != AUTHORIZATION_VERSION) {
            revert InvalidAuthorizationVersion(authorization.version);
        }

        uint64 createdAt = authorization.createdAt;
        uint64 expiresAt = authorization.expiresAt;
        if (block.timestamp < createdAt) revert RequestNotYetValid();
        if (block.timestamp >= expiresAt) revert RequestExpired();
        if (block.timestamp - createdAt > maxRequestAge) revert RequestTooOld();
        if (expiresAt - createdAt > maxRequestLifetime) revert RequestLifetimeTooLong();

        // Matches the OPRF node: a signer without code is an EOA; with code it must be WIP-101.
        if (signer.code.length == 0) {
            if (authorization.wip101Data.length != 0) revert IWIP101.Wip101DataOnEoa();
            bytes memory message =
                abi.encodePacked(AUTHORIZATION_VERSION, authorization.nonce, createdAt, expiresAt, billingAction);
            (address recovered, ECDSA.RecoverError err,) =
                ECDSA.tryRecover(MessageHashUtils.toEthSignedMessageHash(message), authorization.signature);
            if (err != ECDSA.RecoverError.NoError || recovered != signer) revert InvalidRpSignature();
        } else {
            if (authorization.wip101Data.length > MAX_WIP101_DATA_LENGTH) revert IWIP101.Wip101DataTooLong();
            if (!ERC165Checker.supportsInterface(signer, type(IWIP101).interfaceId)) {
                revert IWIP101.Wip101Unsupported();
            }
            // Low-level call so malformed return data maps to `Wip101Rejected` instead of a decode revert.
            (bool ok, bytes memory result) = signer.staticcall(
                abi.encodeCall(
                    IWIP101.verifyRpRequest,
                    (
                        AUTHORIZATION_VERSION,
                        authorization.nonce,
                        createdAt,
                        expiresAt,
                        billingAction,
                        authorization.wip101Data
                    )
                )
            );
            if (!ok || result.length != 32 || bytes32(result) != bytes32(IWIP101.verifyRpRequest.selector)) {
                revert IWIP101.Wip101Rejected();
            }
        }
    }

    ////////////////////////////////////////////////////////////
    //                     CALENDAR MATH                      //
    ////////////////////////////////////////////////////////////

    /// @dev 00:00:00 AoE (12:00:00 UTC) on the first day of the month containing `timestamp`.
    function _monthStart(uint256 timestamp) internal pure returns (uint64) {
        if (timestamp < AOE_OFFSET) revert BillingPeriodBeforeUnixEpoch();
        (uint256 year, uint256 month,) = DateTimeLib.timestampToDate(timestamp - AOE_OFFSET);
        return SafeCast.toUint64(DateTimeLib.dateToTimestamp(year, month, 1) + AOE_OFFSET);
    }

    /// @dev `periodStart + months`; exact because `periodStart` is always the 1st of a month.
    function _addMonths(uint256 periodStart, uint256 months) internal pure returns (uint64) {
        return SafeCast.toUint64(DateTimeLib.addMonths(periodStart, months));
    }
}
