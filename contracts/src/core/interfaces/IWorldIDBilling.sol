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

    /// @notice Identifies one deployment, RP and UTC calendar month.
    struct BillingContext {
        uint256 chainId;
        address billingContract;
        uint64 rpId;
        uint64 periodStart;
    }

    /// @notice RP authorization copied from the billing `ProofRequest` (WIP-107 §4.4).
    struct RegistrationAuthorization {
        uint8 version;
        uint160 oprfKeyId;
        uint256 nonce;
        uint64 createdAt;
        uint64 expiresAt;
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
    struct Period {
        uint256 capacity;
        uint256 registeredCount;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    error InvalidChainId();
    error InvalidBillingContract();
    error NonCanonicalPeriodStart();
    error PeriodOutsidePurchaseWindow();
    error PeriodNotCurrent();
    error ZeroCapacityAmount();
    error MaxWldAmountExceeded(uint256 wldAmount, uint256 maxWldAmount);
    error FeeTransferMismatch(uint256 expected, uint256 received);
    error PriceUnavailable();
    error InvalidPrice();
    error PriceFromFuture(uint256 observedAt);
    error StalePrice(uint256 observedAt);
    error InvalidPricePerWorldID();
    error InvalidMaxPriceAge();
    error InvalidTokenDecimals();
    error InvalidAuthorizationVersion(uint8 version);
    error NonceAlreadyUsed();
    error RequestNotYetValid();
    error RequestExpired();
    error OprfKeyMismatch();
    error InvalidRpSignature();
    error Wip101DataOnEoa();
    error Wip101Unsupported();
    error Wip101DataTooLong();
    error Wip101Rejected();
    error CapacityExhausted();

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

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @notice WLD base units charged for `capacityAmount` at the current verified rate.
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
    function registerMany(BillingContext calldata scope, Registration[] calldata registrations)
        external
        returns (bool[] memory successes);

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @notice Whether `billingNullifier` is registered for the RP and period.
    function isRegistered(uint64 rpId, uint64 periodStart, uint256 billingNullifier) external view returns (bool);

    /// @notice Purchased capacity and registration count for the RP and period.
    function periods(uint64 rpId, uint64 periodStart) external view returns (uint256 capacity, uint256 registeredCount);

    /// @notice Whether an authorization nonce was consumed for the RP and period.
    function usedNonces(uint64 rpId, uint64 periodStart, uint256 nonce) external view returns (bool);

    /// @notice UTC month containing `timestamp`; `periodEnd` is exclusive.
    function getBillingPeriod(uint64 timestamp) external view returns (uint64 periodStart, uint64 periodEnd);

    /// @notice Billing OPRF action for `scope` (WIP-107 §4.2).
    function getBillingAction(BillingContext calldata scope) external pure returns (uint256);

    /// @notice USD price of one registration for one period, scaled by 1e18.
    function pricePerWorldID() external view returns (uint256);
    /// @notice Maximum accepted age of the WLD/USD price, in seconds.
    function maxPriceAge() external view returns (uint64);

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    function setFeeToken(address feeToken) external;
    function setPricePerWorldID(uint256 newPricePerWorldID) external;
    function setMaxPriceAge(uint64 newMaxPriceAge) external;
    function setPriceSource(address newPriceSource) external;

    /// @notice Pauses new registrations; duplicates and purchases are unaffected.
    function setPaused(bool isPaused) external;
}
