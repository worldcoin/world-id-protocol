// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IWorldIDBilling
 * @author World Contributors
 * @notice Per-period World ID registration capacity, purchased by RPs in WLD (WIP-107).
 */
interface IWorldIDBilling {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    /// @notice Identifies one deployment, RP and billing period; registration overlaps adjacent periods.
    struct BillingContext {
        uint256 chainId;
        address billingContract;
        uint64 rpId;
        uint64 periodStart;
    }

    /// @notice RP authorization copied from the RP's own `ProofRequest` (WIP-107 §4.5); `signedAction` is the
    ///  request's action, while the registration proof uses the derived billing action.
    struct RegistrationAuthorization {
        uint8 version;
        uint160 oprfKeyId;
        uint256 nonce;
        uint64 createdAt;
        uint64 expiresAt;
        uint256 signedAction;
        bytes signature;
        bytes wip101Data;
    }

    /// @notice One entry of `registerMany`; fields match the `register` arguments.
    struct Registration {
        RegistrationAuthorization authorization;
        uint64 issuerSchemaId;
        uint64 expiresAtMin;
        uint256 billingNullifier;
        uint256[5] proof;
    }

    /// @notice Purchased capacity and registrations for one RP and period.
    struct PeriodCapacity {
        uint256 capacity;
        uint256 registeredCount;
    }

    /// @notice RP OPRF key pinned by the first registration in a period (WIP-107 §4.4.2).
    struct PinnedOprfKey {
        uint160 oprfKeyId;
        uint256 x;
        uint256 y;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    error InvalidChainId();
    error InvalidBillingContract();
    error NonCanonicalPeriodStart();
    error BillingPeriodBeforeUnixEpoch();
    error PeriodOutsidePurchaseWindow();
    error PeriodNotCurrent();
    error ZeroCapacityAmount();
    error MaxWldAmountExceeded(uint256 wldAmount, uint256 maxWldAmount);
    error FeeTransferMismatch(uint256 expected, uint256 received);
    error PriceUnavailable();
    error InvalidPrice();
    error InvalidPriceDecimals(uint8 decimals);
    error PriceFromFuture(uint256 observedAt);
    error StalePrice(uint256 observedAt);
    error InvalidPricePerWorldID();
    error InvalidMaxPriceAge();
    error InvalidRequestLimits();
    error InvalidTokenDecimals();
    error InvalidAuthorizationVersion(uint8 version);
    error NonceAlreadyUsed();
    error RequestNotYetValid();
    error RequestExpired();
    error RequestTooOld();
    error RequestLifetimeTooLong();
    error OprfKeyMismatch();
    error PinnedOprfKeyChanged();
    error CapacityExhausted();
    error RegistrationFeeUnsupported();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    event CapacityPurchased(
        uint64 indexed rpId, uint64 indexed periodStart, address indexed payer, uint256 capacityAmount, uint256 wldPaid
    );
    event Registered(uint64 indexed rpId, uint64 indexed periodStart, uint256 billingNullifier);

    event PricePerWorldIDUpdated(uint256 oldPricePerWorldID, uint256 newPricePerWorldID);
    event MaxPriceAgeUpdated(uint64 oldMaxPriceAge, uint64 newMaxPriceAge);
    event PriceSourceUpdated(address oldPriceSource, address newPriceSource);
    event RequestLimitsUpdated(
        uint64 oldMaxRequestAge, uint64 oldMaxRequestLifetime, uint64 newMaxRequestAge, uint64 newMaxRequestLifetime
    );
    event OprfKeyPinned(uint64 indexed rpId, uint64 indexed periodStart, uint160 oprfKeyId);

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice WLD base units charged at the verified rate, prorated by seconds remaining in the AoE month.
    function quotePurchase(BillingContext calldata scope, uint256 capacityAmount)
        external
        view
        returns (uint256 wldAmount);

    /// @notice Buys `capacityAmount` registrations for `scope`, paying at most `maxWldAmount` WLD.
    function purchaseCapacity(BillingContext calldata scope, uint256 capacityAmount, uint256 maxWldAmount) external;

    /// @notice Registers `billingNullifier` for `scope`; returns false for an already registered nullifier.
    function register(
        BillingContext calldata scope,
        RegistrationAuthorization calldata authorization,
        uint64 issuerSchemaId,
        uint64 expiresAtMin,
        uint256 billingNullifier,
        uint256[5] calldata proof
    ) external returns (bool success);

    /// @notice Registers each entry for `scope` as `register` would; reverts entirely if any entry fails.
    /// @dev Atomic per WIP-107 §4.2. If anyone submits a copy of an entry first, its nonce is consumed and the whole
    ///  batch reverts; relayers should then resubmit the remaining entries.
    function registerMany(BillingContext calldata scope, Registration[] calldata registrations)
        external
        returns (bool[] memory successes);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @notice Whether `billingNullifier` is registered; `billingAction` already scopes it to one RP and period.
    function isRegistered(uint256 billingNullifier) external view returns (bool);

    /// @notice Purchased capacity and registration count for the RP and period.
    function getPeriodCapacity(uint64 rpId, uint64 periodStart)
        external
        view
        returns (uint256 capacity, uint256 registeredCount);

    /// @notice Whether an authorization nonce was consumed for the RP.
    function usedNonces(uint64 rpId, uint256 nonce) external view returns (bool);

    /// @notice OPRF key pinned for the RP and period; zero until the period's first registration.
    function getPinnedOprfKey(uint64 rpId, uint64 periodStart)
        external
        view
        returns (uint160 oprfKeyId, uint256[2] memory oprfPublicKey);

    /// @notice AoE month containing `timestamp`; `periodEnd` is exclusive and registration opens 26 hours early.
    function getBillingPeriod(uint64 timestamp) external view returns (uint64 periodStart, uint64 periodEnd);

    /// @notice Billing OPRF action for `scope` (WIP-107 §4.3).
    function getBillingAction(BillingContext calldata scope) external pure returns (uint256);

    /// @notice WLD ERC-20 in which capacity is paid.
    function getFeeToken() external view returns (address);
    /// @notice Protocol fee address that receives purchase payments.
    function getFeeRecipient() external view returns (address);
    /// @notice Proxy owner and billing administrator.
    function owner() external view returns (address);
    /// @notice Whether purchases and new registrations are paused.
    function paused() external view returns (bool);

    /// @notice WLD/USD adapter for verified Data Streams reports (WIP-107 §4.9).
    function priceSource() external view returns (address);
    /// @notice USD price of one registration for one period, scaled by 1e18.
    function pricePerWorldID() external view returns (uint256);
    /// @notice Maximum accepted age of the WLD/USD price, in seconds.
    function maxPriceAge() external view returns (uint64);
    /// @notice Maximum accepted `now - createdAt` of an authorization, in seconds; matches the OPRF nodes.
    function maxRequestAge() external view returns (uint64);
    /// @notice Maximum accepted `expiresAt - createdAt` of an authorization, in seconds; matches the OPRF nodes.
    function maxRequestLifetime() external view returns (uint64);

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    function setFeeToken(address feeToken) external;
    function setFeeRecipient(address feeRecipient) external;
    function setPricePerWorldID(uint256 newPricePerWorldID) external;
    function setMaxPriceAge(uint64 newMaxPriceAge) external;
    function setPriceSource(address newPriceSource) external;
    function setRequestLimits(uint64 newMaxRequestAge, uint64 newMaxRequestLifetime) external;

    /// @notice Pauses purchases and new registrations; registering a duplicate is unaffected.
    function setPaused(bool isPaused) external;
}
