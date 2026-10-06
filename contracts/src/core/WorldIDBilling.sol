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
import {WorldIDBase} from "./abstract/WorldIDBase.sol";
import {IWorldIDVerifier} from "./interfaces/IWorldIDVerifier.sol";
import {IRpRegistry} from "./interfaces/IRpRegistry.sol";
import {IWorldIDBilling} from "./interfaces/IWorldIDBilling.sol";
import {IChainlinkAggregator} from "./interfaces/IChainlinkAggregator.sol";
import {IWIP101} from "./interfaces/IWIP101.sol";

/// @title WorldIDBilling
/// @author World Contributors
/// @notice Sells per-RP, per-UTC-month registration capacity in WLD and records billing nullifiers (WIP-107).
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
    mapping(uint64 rpId => mapping(uint64 periodStart => mapping(uint256 billingNullifier => bool))) public
        isRegistered;

    /// @inheritdoc IWorldIDBilling
    mapping(uint64 rpId => mapping(uint64 periodStart => mapping(uint256 nonce => bool))) public usedNonces;

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
     */
    function initialize(
        address initialPriceSource,
        address feeToken,
        address feeRecipient,
        uint256 initialPricePerWorldID,
        uint64 initialMaxPriceAge
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
    }

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDBilling
    function purchaseCapacity(BillingContext calldata scope, uint256 capacityAmount, uint256 maxWldAmount)
        external
        virtual
        onlyProxy
        onlyInitialized
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
    ) external virtual onlyProxy onlyInitialized nonReentrant returns (bool success) {
        _validateScope(scope);
        // Registration is limited to the current period; purchases may run ahead.
        if (scope.periodStart != _monthStart(block.timestamp)) revert PeriodNotCurrent();

        mapping(uint256 => bool) storage nonces = usedNonces[scope.rpId][scope.periodStart];
        if (nonces[authorization.nonce]) revert NonceAlreadyUsed();
        nonces[authorization.nonce] = true;

        uint256 billingAction = getBillingAction(scope);
        (uint160 oprfKeyId, address signer) = RP_REGISTRY.getOprfKeyIdAndSigner(scope.rpId);
        if (authorization.oprfKeyId != oprfKeyId) revert OprfKeyMismatch();

        _verifyAuthorization(authorization, signer, billingAction);

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

        mapping(uint256 => bool) storage registered = isRegistered[scope.rpId][scope.periodStart];
        if (registered[billingNullifier]) return false;

        // Duplicates above still succeed while paused; only new registrations stop.
        _requireNotPaused();
        Period storage period = periods[scope.rpId][scope.periodStart];
        if (period.registeredCount >= period.capacity) revert CapacityExhausted();

        period.registeredCount += 1;
        registered[billingNullifier] = true;
        emit Registered(scope.rpId, scope.periodStart, billingNullifier);
        return true;
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
        onlyInitialized
        returns (uint256 wldAmount)
    {
        _validateScope(scope);
        if (capacityAmount == 0) revert ZeroCapacityAmount();

        uint256 currentStart = _monthStart(block.timestamp);
        uint64 secondNext = _addMonths(currentStart, 2);
        if (scope.periodStart < currentStart || scope.periodStart > secondNext) revert PeriodOutsidePurchaseWindow();

        uint256 usdPerWld = _verifiedUsdPerWld();
        uint256 usdTotal = capacityAmount * pricePerWorldID;
        return Math.mulDiv(usdTotal, TOKEN_UNIT, usdPerWld, Math.Rounding.Ceil);
    }

    /// @inheritdoc IWorldIDBilling
    function getBillingPeriod(uint64 timestamp) external pure virtual returns (uint64 periodStart, uint64 periodEnd) {
        periodStart = _monthStart(timestamp);
        periodEnd = _addMonths(periodStart, 1);
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
        onlyInitialized
    {
        if (newFeeToken == address(0)) revert ZeroAddress();
        if (IERC20Metadata(newFeeToken).decimals() != TOKEN_DECIMALS) revert InvalidTokenDecimals();
        address oldToken = address(_feeToken);
        _feeToken = IERC20(newFeeToken);
        emit FeeTokenUpdated(oldToken, newFeeToken);
    }

    /// @inheritdoc IWorldIDBilling
    function setPricePerWorldID(uint256 newPricePerWorldID) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newPricePerWorldID == 0) revert InvalidPricePerWorldID();
        emit PricePerWorldIDUpdated(pricePerWorldID, newPricePerWorldID);
        pricePerWorldID = newPricePerWorldID;
    }

    /// @inheritdoc IWorldIDBilling
    function setMaxPriceAge(uint64 newMaxPriceAge) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newMaxPriceAge == 0) revert InvalidMaxPriceAge();
        emit MaxPriceAgeUpdated(maxPriceAge, newMaxPriceAge);
        maxPriceAge = newMaxPriceAge;
    }

    /// @inheritdoc IWorldIDBilling
    function setPriceSource(address newPriceSource) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newPriceSource == address(0)) revert ZeroAddress();
        emit PriceSourceUpdated(address(_priceSource), newPriceSource);
        _priceSource = IChainlinkAggregator(newPriceSource);
    }

    /// @inheritdoc IWorldIDBilling
    function setPaused(bool isPaused) external virtual onlyOwner onlyProxy onlyInitialized {
        if (isPaused) _pause();
        else _unpause();
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /// @dev Reads the feed and normalizes it to USD per WLD scaled by 1e18. `updatedAt` is the report's
    ///  observation time, not the submission time.
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

        // Matches the OPRF node: a signer without code is an EOA; with code it must be WIP-101.
        if (signer.code.length == 0) {
            if (authorization.wip101Data.length != 0) revert Wip101DataOnEoa();
            bytes memory message =
                abi.encodePacked(AUTHORIZATION_VERSION, authorization.nonce, createdAt, expiresAt, billingAction);
            (address recovered, ECDSA.RecoverError err,) =
                ECDSA.tryRecover(MessageHashUtils.toEthSignedMessageHash(message), authorization.signature);
            if (err != ECDSA.RecoverError.NoError || recovered != signer) revert InvalidRpSignature();
        } else {
            if (authorization.wip101Data.length > MAX_WIP101_DATA_LENGTH) revert Wip101DataTooLong();
            if (!ERC165Checker.supportsInterface(signer, type(IWIP101).interfaceId)) revert Wip101Unsupported();
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
                revert Wip101Rejected();
            }
        }
    }

    ////////////////////////////////////////////////////////////
    //                     CALENDAR MATH                      //
    ////////////////////////////////////////////////////////////

    /// @dev 00:00:00 UTC on the first day of the month containing `timestamp`.
    function _monthStart(uint256 timestamp) internal pure returns (uint64) {
        (uint256 year, uint256 month,) = DateTimeLib.timestampToDate(timestamp);
        return SafeCast.toUint64(DateTimeLib.dateToTimestamp(year, month, 1));
    }

    /// @dev `periodStart + months`; exact because `periodStart` is always the 1st of a month.
    function _addMonths(uint256 periodStart, uint256 months) internal pure returns (uint64) {
        return SafeCast.toUint64(DateTimeLib.addMonths(periodStart, months));
    }
}
