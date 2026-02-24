// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IAddressBook
 * @author World Contributors
 * @notice Soft-cache contract for period-scoped World ID verification results.
 */
interface IAddressBook {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Logical verification context (period excluded).
     * @param rpId Registered RP identifier.
     * @param action RP-defined action field value used by World ID proofs.
     */
    struct EpochData {
        uint64 rpId;
        uint256 action;
    }

    /**
     * @notice World ID proof payload needed for registration.
     */
    struct RegistrationProof {
        uint256 nullifier;
        uint256 nonce;
        uint64 expiresAtMin;
        uint64 issuerSchemaId;
        uint256 credentialGenesisIssuedAtMin;
        uint256[5] zeroKnowledgeProof;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    error InvalidPeriodLength();
    error PeriodNotStarted();
    error PeriodOutOfRange();
    error InvalidAccount();
    error InvalidAccountAuthorization();
    error InvalidTargetPeriod(uint32 targetPeriod, uint32 currentPeriod);
    error NullifierAlreadyUsed(uint256 nullifier, bytes32 epochId);
    error AddressAlreadyRegistered(address account, bytes32 epochId);

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Emitted when an address is registered for a period/rp/action context.
     */
    event AddressRegistered(
        bytes32 indexed epochId,
        uint32 indexed period,
        uint64 indexed rpId,
        uint256 action,
        address account,
        uint256 nullifier
    );

    /**
     * @notice Emitted when the WorldID verifier contract is updated.
     */
    event WorldIDVerifierUpdated(address oldWorldIDVerifier, address newWorldIDVerifier);

    /**
     * @notice Emitted when registration period guard is toggled.
     */
    event EnforceCurrentOrNextPeriodUpdated(bool oldValue, bool newValue);

    ////////////////////////////////////////////////////////////
    //                   EXTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Registers an address for the given target period and context.
     * @dev Caller must be the same as `account`.
     */
    function register(address account, uint32 targetPeriod, EpochData calldata epoch, RegistrationProof calldata proof)
        external;

    /**
     * @notice Relayed registration with account authorization signature.
     */
    function registerWithSignature(
        address account,
        uint32 targetPeriod,
        EpochData calldata epoch,
        RegistrationProof calldata proof,
        bytes calldata accountSignature
    ) external;

    /**
     * @notice Returns whether `account` is registered in the currently active period for this context.
     */
    function verify(EpochData calldata epoch, address account) external view returns (bool);

    /**
     * @notice Raw lookup for an explicit period.
     */
    function isRegisteredForPeriod(uint32 period, EpochData calldata epoch, address account)
        external
        view
        returns (bool);

    /**
     * @notice Returns the currently active period index.
     */
    function getCurrentPeriod() external view returns (uint32);

    /**
     * @notice Computes the epoch key for the given period and context.
     */
    function computeEpochId(uint32 period, EpochData calldata epoch) external pure returns (bytes32);

    /**
     * @notice Computes the canonical signal string for period/context/account.
     */
    function computeSignal(uint32 period, EpochData calldata epoch, address account)
        external
        view
        returns (string memory);

    /**
     * @notice Computes the signal hash bound to period/context/account.
     */
    function computeSignalHash(uint32 period, EpochData calldata epoch, address account) external view returns (uint256);

    /**
     * @notice Computes EIP-712 digest that an account must sign for relayed registration.
     */
    function computeRegistrationDigest(address account, uint32 targetPeriod, EpochData calldata epoch)
        external
        view
        returns (bytes32);

    /**
     * @notice Returns the WorldID verifier address.
     */
    function getWorldIDVerifier() external view returns (address);

    /**
     * @notice Returns the configured period start timestamp.
     */
    function getPeriodStartTimestamp() external view returns (uint64);

    /**
     * @notice Returns the configured period length in seconds.
     */
    function getPeriodLengthSeconds() external view returns (uint64);

    /**
     * @notice Returns whether registration is limited to current or next period.
     */
    function getEnforceCurrentOrNextPeriod() external view returns (bool);

    ////////////////////////////////////////////////////////////
    //                     OWNER FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Updates the WorldID verifier address.
     */
    function updateWorldIDVerifier(address newWorldIDVerifier) external;

    /**
     * @notice Toggles whether registration is restricted to current/next period.
     */
    function setEnforceCurrentOrNextPeriod(bool enabled) external;
}
