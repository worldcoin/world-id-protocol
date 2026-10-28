// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
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
import {RpRequestAuth} from "./libraries/RpRequestAuth.sol";

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

    /// @dev USD per World ID per period, scaled by 1e18.
    uint256 internal _pricePerWorldID;

    /// @dev Maximum accepted age of the WLD/USD price, in seconds.
    uint64 internal _maxPriceAge;

    /// @dev Purchased capacity and registration count per RP and period.
    mapping(uint64 rpId => mapping(uint64 periodStart => PeriodCapacity)) internal _capacities;

    /// @dev Registered billing nullifiers; `billingAction` already scopes each to one RP and period.
    mapping(uint256 billingNullifier => bool) internal _isRegistered;

    /// @dev Consumed authorization nonces per RP.
    mapping(uint64 rpId => mapping(uint256 nonce => bool)) internal _usedNonces;

    /// @dev OPRF key pinned by the first registration for each RP and period.
    mapping(uint64 rpId => mapping(uint64 periodStart => PinnedOprfKey)) internal _pinnedOprfKeys;

    /// @dev Maximum accepted `now - createdAt` of an authorization, in seconds.
    uint64 internal _maxRequestAge;

    /// @dev Maximum accepted `expiresAt - createdAt` of an authorization, in seconds.
    uint64 internal _maxRequestLifetime;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "WorldIDBilling";
    string public constant EIP712_VERSION = "1.0";

    string public constant BILLING_ACTION_DOMAIN = "world-id-billing-v1";

    uint8 public constant AUTHORIZATION_VERSION = RpRequestAuth.VERSION;

    uint256 public constant MAX_WIP101_DATA_LENGTH = RpRequestAuth.MAX_WIP101_DATA_LENGTH;

    /// @notice Decimals of the WLD/USD price source; WIP-107 §4.9 requires USD scaled by 1e18.
    uint8 public constant PRICE_DECIMALS = 18;

    /// @notice Decimals of the WLD fee token; `setFeeToken` rejects tokens with other decimals.
    uint8 public constant TOKEN_DECIMALS = 18;

    uint256 internal constant TOKEN_UNIT = 10 ** TOKEN_DECIMALS;

    uint256 internal constant AOE_OFFSET = 12 hours;

    uint256 internal constant PERIOD_OVERLAP = 26 hours;

    /// @dev Longest AoE month; bounds `duration * usdPerWld` in `quotePurchase`.
    uint256 internal constant MAX_PERIOD_DURATION = 31 days;

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
     * @param initialPriceSource WLD/USD adapter for verified Data Streams reports, with 18 decimals (WIP-107 §4.9).
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
        if (feeToken == address(0)) revert ZeroAddress();
        if (feeRecipient == address(0)) revert ZeroAddress();

        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, feeRecipient, feeToken, 0);
        __Pausable_init();

        if (IERC20Metadata(feeToken).decimals() != TOKEN_DECIMALS) revert InvalidTokenDecimals();
        if (initialPricePerWorldID == 0) revert InvalidPricePerWorldID();
        if (initialMaxPriceAge == 0) revert InvalidMaxPriceAge();

        _setPriceSource(initialPriceSource);
        _pricePerWorldID = initialPricePerWorldID;
        _maxPriceAge = initialMaxPriceAge;
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
        onlyInitialized
        nonReentrant
        whenNotPaused
    {
        // Payment must not buy unusable capacity: reject unknown or inactive RPs, and periods frozen by an OPRF
        // key change, which reject every registration until they end (WIP-107 §4.9).
        (uint160 oprfKeyId,) = RP_REGISTRY.getOprfKeyIdAndSigner(scope.rpId);
        _requireCurrentKeyMatchesPin(scope, oprfKeyId);
        uint256 wldPaid = quotePurchase(scope, capacityAmount);
        if (wldPaid > maxWldAmount) revert MaxWldAmountExceeded(wldPaid, maxWldAmount);

        _capacities[scope.rpId][scope.periodStart].capacity += capacityAmount;

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
        uint256 billingAction = _validateRegistrationContext(scope);
        return _register(scope, billingAction, authorization, issuerSchemaId, expiresAtMin, billingNullifier, proof);
    }

    /// @inheritdoc IWorldIDBilling
    function registerMany(BillingContext calldata scope, Registration[] calldata registrations)
        external
        virtual
        onlyProxy
        onlyInitialized
        nonReentrant
        returns (bool[] memory successes)
    {
        // Validated once for the batch, so an empty batch still rejects an invalid or inactive context.
        uint256 billingAction = _validateRegistrationContext(scope);
        successes = new bool[](registrations.length);
        for (uint256 i = 0; i < registrations.length; ++i) {
            Registration calldata registration = registrations[i];
            successes[i] = _register(
                scope,
                billingAction,
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
        onlyInitialized
        returns (uint256 wldAmount)
    {
        _validateScope(scope);
        if (capacityAmount == 0) revert ZeroCapacityAmount();

        uint256 currentStart = _monthStart(block.timestamp);
        uint64 nextStart = _addMonths(currentStart, 1);
        if (scope.periodStart < currentStart || scope.periodStart > nextStart) revert PeriodOutsidePurchaseWindow();

        uint256 usdPerWld = _verifiedUsdPerWld();
        uint256 usdTotal = capacityAmount * _pricePerWorldID;
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
        onlyProxy
        onlyInitialized
        returns (uint160 oprfKeyId, uint256[2] memory oprfPublicKey)
    {
        PinnedOprfKey storage pinned = _pinnedOprfKeys[rpId][periodStart];
        return (pinned.oprfKeyId, [pinned.x, pinned.y]);
    }

    /// @inheritdoc IWorldIDBilling
    function isRegistered(uint256 billingNullifier) external view virtual onlyProxy onlyInitialized returns (bool) {
        return _isRegistered[billingNullifier];
    }

    /// @inheritdoc IWorldIDBilling
    function getPeriodCapacity(uint64 rpId, uint64 periodStart)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256 capacity, uint256 registeredCount)
    {
        PeriodCapacity storage period = _capacities[rpId][periodStart];
        return (period.capacity, period.registeredCount);
    }

    /// @inheritdoc IWorldIDBilling
    function usedNonces(uint64 rpId, uint256 nonce) external view virtual onlyProxy onlyInitialized returns (bool) {
        return _usedNonces[rpId][nonce];
    }

    /// @inheritdoc IWorldIDBilling
    function getFeeToken()
        external
        view
        virtual
        override(WorldIDBase, IWorldIDBilling)
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return address(_feeToken);
    }

    /// @inheritdoc IWorldIDBilling
    function getFeeRecipient()
        external
        view
        virtual
        override(WorldIDBase, IWorldIDBilling)
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _feeRecipient;
    }

    /// @inheritdoc IWorldIDBilling
    function owner() public view virtual override(OwnableUpgradeable, IWorldIDBilling) returns (address) {
        return super.owner();
    }

    /// @inheritdoc IWorldIDBilling
    function paused() public view virtual override(PausableUpgradeable, IWorldIDBilling) returns (bool) {
        return super.paused();
    }

    /// @inheritdoc IWorldIDBilling
    function priceSource() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_priceSource);
    }

    /// @inheritdoc IWorldIDBilling
    function pricePerWorldID() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _pricePerWorldID;
    }

    /// @inheritdoc IWorldIDBilling
    function maxPriceAge() external view virtual onlyProxy onlyInitialized returns (uint64) {
        return _maxPriceAge;
    }

    /// @inheritdoc IWorldIDBilling
    function maxRequestAge() external view virtual onlyProxy onlyInitialized returns (uint64) {
        return _maxRequestAge;
    }

    /// @inheritdoc IWorldIDBilling
    function maxRequestLifetime() external view virtual onlyProxy onlyInitialized returns (uint64) {
        return _maxRequestLifetime;
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
    function setFeeRecipient(address newFeeRecipient)
        external
        virtual
        override(WorldIDBase, IWorldIDBilling)
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        if (newFeeRecipient == address(0)) revert ZeroAddress();
        address oldRecipient = _feeRecipient;
        _feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldRecipient, newFeeRecipient);
    }

    /// @inheritdoc IWorldIDBilling
    function setPricePerWorldID(uint256 newPricePerWorldID) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newPricePerWorldID == 0) revert InvalidPricePerWorldID();
        emit PricePerWorldIDUpdated(_pricePerWorldID, newPricePerWorldID);
        _pricePerWorldID = newPricePerWorldID;
    }

    /// @inheritdoc IWorldIDBilling
    function setMaxPriceAge(uint64 newMaxPriceAge) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newMaxPriceAge == 0) revert InvalidMaxPriceAge();
        emit MaxPriceAgeUpdated(_maxPriceAge, newMaxPriceAge);
        _maxPriceAge = newMaxPriceAge;
    }

    /// @inheritdoc IWorldIDBilling
    function setPriceSource(address newPriceSource) external virtual onlyOwner onlyProxy onlyInitialized {
        _setPriceSource(newPriceSource);
    }

    /// @inheritdoc IWorldIDBilling
    function setRequestLimits(uint64 newMaxRequestAge, uint64 newMaxRequestLifetime)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        _setRequestLimits(newMaxRequestAge, newMaxRequestLifetime);
    }

    /// @inheritdoc IWorldIDBilling
    function setPaused(bool isPaused) external virtual onlyOwner onlyProxy onlyInitialized {
        if (isPaused) _pause();
        else _unpause();
    }

    /// @notice Unsupported: billing charges only through `purchaseCapacity`, never a per-call registration fee.
    function setRegistrationFee(uint256) external virtual override onlyOwner onlyProxy onlyInitialized {
        revert RegistrationFeeUnsupported();
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /// @dev Validates the context shared by every entry of a call and returns its billing action.
    function _validateRegistrationContext(BillingContext calldata scope) internal view virtual returns (uint256) {
        _validateScope(scope);
        if (block.timestamp + PERIOD_OVERLAP < scope.periodStart || block.timestamp >= _addMonths(scope.periodStart, 1))
        {
            revert PeriodNotCurrent();
        }
        return getBillingAction(scope);
    }

    /// @dev Registers one entry; `scope` must already pass `_validateRegistrationContext`.
    function _register(
        BillingContext calldata scope,
        uint256 billingAction,
        RegistrationAuthorization calldata authorization,
        uint64 issuerSchemaId,
        uint64 expiresAtMin,
        uint256 billingNullifier,
        uint256[5] calldata proof
    ) internal virtual returns (bool) {
        mapping(uint256 => bool) storage nonces = _usedNonces[scope.rpId];
        if (nonces[authorization.nonce]) revert NonceAlreadyUsed();

        (uint160 oprfKeyId, address signer) = RP_REGISTRY.getOprfKeyIdAndSigner(scope.rpId);
        if (authorization.oprfKeyId != oprfKeyId) revert OprfKeyMismatch();

        // The RP signs its own action; the proof uses the derived `billingAction` (WIP-107 §4.5).
        _verifyAuthorization(authorization, signer);
        nonces[authorization.nonce] = true;
        _pinOprfKey(scope, oprfKeyId);

        // Uniqueness Proof with signal, genesis minimum and session set to zero (WIP-107 §4.4.1). `expiresAtMin` is the
        // credential expiry lower bound the proof attests; it cannot be zero, because the verifier enforces its
        // freshness policy (`ExpirationTooOld`).
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

        if (_isRegistered[billingNullifier]) return false;

        // Duplicates above still succeed while paused; only new registrations stop.
        _requireNotPaused();
        PeriodCapacity storage period = _capacities[scope.rpId][scope.periodStart];
        if (period.registeredCount >= period.capacity) revert CapacityExhausted();

        period.registeredCount += 1;
        _isRegistered[billingNullifier] = true;
        emit Registered(scope.rpId, scope.periodStart, billingNullifier);
        return true;
    }

    /// @dev Pins the RP's OPRF key on the period's first registration. Later registrations require the same key,
    ///  because `WORLD_ID_VERIFIER` checks proofs against the registry's current key.
    function _pinOprfKey(BillingContext calldata scope, uint160 oprfKeyId) internal virtual {
        (bool pinned, BabyJubJub.Affine memory key) = _requireCurrentKeyMatchesPin(scope, oprfKeyId);
        if (!pinned) {
            _pinnedOprfKeys[scope.rpId][scope.periodStart] = PinnedOprfKey(oprfKeyId, key.x, key.y);
            emit OprfKeyPinned(scope.rpId, scope.periodStart, oprfKeyId);
        }
    }

    /// @dev Resolves the RP's current OPRF key and reverts unless it satisfies the period's pin, if any.
    function _requireCurrentKeyMatchesPin(BillingContext calldata scope, uint160 oprfKeyId)
        internal
        view
        virtual
        returns (bool pinned, BabyJubJub.Affine memory key)
    {
        // `WORLD_ID_VERIFIER` reads the key at `uint160(rpId)`, so the pin must cover that key.
        if (oprfKeyId != uint160(scope.rpId)) revert OprfKeyMismatch();
        key = OprfKeyRegistry(WORLD_ID_VERIFIER.getOprfKeyRegistry()).getOprfPublicKey(oprfKeyId);
        // (0, 0) is not on BabyJubJub, so it marks an unpinned period and is never a valid key.
        if (key.x == 0 && key.y == 0) revert OprfKeyMismatch();
        PinnedOprfKey storage pin = _pinnedOprfKeys[scope.rpId][scope.periodStart];
        pinned = pin.x != 0 || pin.y != 0;
        if (pinned && (pin.oprfKeyId != oprfKeyId || pin.x != key.x || pin.y != key.y)) {
            revert PinnedOprfKeyChanged();
        }
    }

    function _setRequestLimits(uint64 newMaxRequestAge, uint64 newMaxRequestLifetime) internal virtual {
        if (newMaxRequestAge == 0 || newMaxRequestLifetime == 0) revert InvalidRequestLimits();
        emit RequestLimitsUpdated(_maxRequestAge, _maxRequestLifetime, newMaxRequestAge, newMaxRequestLifetime);
        _maxRequestAge = newMaxRequestAge;
        _maxRequestLifetime = newMaxRequestLifetime;
    }

    /// @dev Accepts only a §4.9 adapter, which already normalizes to USD scaled by 1e18.
    function _setPriceSource(address newPriceSource) internal virtual {
        if (newPriceSource == address(0)) revert ZeroAddress();
        uint8 decimals = IChainlinkAggregator(newPriceSource).decimals();
        if (decimals != PRICE_DECIMALS) revert InvalidPriceDecimals(decimals);
        emit PriceSourceUpdated(address(_priceSource), newPriceSource);
        _priceSource = IChainlinkAggregator(newPriceSource);
    }

    /// @dev Reads the verified USD per WLD, scaled by 1e18. `updatedAt` is the report's observation time, not the
    ///  submission time.
    function _verifiedUsdPerWld() internal view virtual returns (uint256) {
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
        if (feedDecimals != PRICE_DECIMALS) revert InvalidPriceDecimals(feedDecimals);
        // The upper bound keeps `duration * usdPerWld` in `quotePurchase` from overflowing.
        if (answer <= 0 || uint256(answer) > type(uint256).max / MAX_PERIOD_DURATION) revert InvalidPrice();
        if (observedAt > block.timestamp) revert PriceFromFuture(observedAt);
        if (block.timestamp - observedAt > _maxPriceAge) revert StalePrice(observedAt);
        return uint256(answer);
    }

    function _validateScope(BillingContext calldata scope) internal view virtual {
        if (scope.chainId != block.chainid) revert InvalidChainId();
        if (scope.billingContract != address(this)) revert InvalidBillingContract();
        if (scope.periodStart != _monthStart(scope.periodStart)) revert NonCanonicalPeriodStart();
    }

    /// @dev Checks the request as OPRF nodes do, with `signedAction` as the action (WIP-107 §4.5).
    function _verifyAuthorization(RegistrationAuthorization calldata authorization, address signer)
        internal
        view
        virtual
    {
        if (authorization.version != AUTHORIZATION_VERSION) {
            revert InvalidAuthorizationVersion(authorization.version);
        }

        uint64 createdAt = authorization.createdAt;
        uint64 expiresAt = authorization.expiresAt;
        if (block.timestamp < createdAt) revert RequestNotYetValid();
        if (block.timestamp >= expiresAt) revert RequestExpired();
        if (block.timestamp - createdAt > _maxRequestAge) revert RequestTooOld();
        if (expiresAt - createdAt > _maxRequestLifetime) revert RequestLifetimeTooLong();

        RpRequestAuth.verify(
            signer,
            authorization.nonce,
            createdAt,
            expiresAt,
            authorization.signedAction,
            authorization.signature,
            authorization.wip101Data
        );
    }

    ////////////////////////////////////////////////////////////
    //                     CALENDAR MATH                      //
    ////////////////////////////////////////////////////////////

    /// @dev 00:00:00 AoE (12:00:00 UTC) on the first day of the month containing `timestamp`.
    function _monthStart(uint256 timestamp) internal pure virtual returns (uint64) {
        if (timestamp < AOE_OFFSET) revert BillingPeriodBeforeUnixEpoch();
        (uint256 year, uint256 month,) = DateTimeLib.timestampToDate(timestamp - AOE_OFFSET);
        return SafeCast.toUint64(DateTimeLib.dateToTimestamp(year, month, 1) + AOE_OFFSET);
    }

    /// @dev `periodStart + months`; exact because `periodStart` is always the 1st of a month.
    function _addMonths(uint256 periodStart, uint256 months) internal pure virtual returns (uint64) {
        return SafeCast.toUint64(DateTimeLib.addMonths(periodStart, months));
    }
}
