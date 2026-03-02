// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {WorldIDBase} from "../core/abstract/WorldIDBase.sol";
import {IWorldIDVerifier} from "../core/interfaces/IWorldIDVerifier.sol";
import {IAddressBook} from "./interfaces/IAddressBook.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title AddressBook
 * @author World Contributors
 * @notice Action-scoped soft-cache for World ID proof verifications.
 * @dev Designed for proxy deployments (UUPS via WorldIDBase).
 */
contract AddressBook is WorldIDBase, IAddressBook {
    ////////////////////////////////////////////////////////////
    //                        MEMBERS                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place.

    /// @dev World ID verifier used by register() to validate proofs.
    IWorldIDVerifier internal _worldIDVerifier;

    /// @dev Unix timestamp marking period 0 start.
    uint64 internal _periodStartTimestamp;

    /// @dev Fixed period length in seconds.
    uint64 internal _periodLengthSeconds;

    /// @dev If true, registration is limited to current or next period only.
    bool internal _enforceCurrentOrNextPeriod;

    /// @dev epochId => account => registered.
    mapping(bytes32 => mapping(address => bool)) internal _epochAddressRegistered;

    /// @dev epochId => nullifier => used.
    mapping(bytes32 => mapping(uint256 => bool)) internal _epochNullifierUsed;

    ////////////////////////////////////////////////////////////
    //                       CONSTANTS                        //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "AddressBook";
    string public constant EIP712_VERSION = "1.0";

    ////////////////////////////////////////////////////////////
    //                      CONSTRUCTOR                       //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    ////////////////////////////////////////////////////////////
    //                      INITIALIZER                       //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Initializes the AddressBook contract.
     * @param worldIDVerifier Address of WorldIDVerifier.
     * @param periodStartTimestamp Start timestamp for period 0.
     * @param periodLengthSeconds Period length in seconds.
     * @param enforceCurrentOrNextPeriod Whether to restrict registration to current/next period.
     */
    function initialize(
        address worldIDVerifier,
        uint64 periodStartTimestamp,
        uint64 periodLengthSeconds,
        bool enforceCurrentOrNextPeriod
    ) public virtual initializer {
        if (worldIDVerifier == address(0)) revert ZeroAddress();
        if (periodLengthSeconds == 0) revert InvalidPeriodLength();

        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, address(0), address(0), 0);

        _worldIDVerifier = IWorldIDVerifier(worldIDVerifier);
        _periodStartTimestamp = periodStartTimestamp;
        _periodLengthSeconds = periodLengthSeconds;
        _enforceCurrentOrNextPeriod = enforceCurrentOrNextPeriod;
    }

    ////////////////////////////////////////////////////////////
    //                   EXTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IAddressBook
    function register(address account, uint32 targetPeriod, EpochData calldata epoch, RegistrationProof calldata proof)
        external
        virtual
        onlyProxy
        onlyInitialized
    {
        if (account == address(0)) revert InvalidAccount();
        _register(account, targetPeriod, epoch, proof);
    }

    /// @inheritdoc IAddressBook
    function verify(EpochData calldata epoch, address account)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bool)
    {
        _getCurrentPeriod();
        bytes32 epochId = _computeEpochId(epoch.action);
        return _epochAddressRegistered[epochId][account];
    }

    /// @inheritdoc IAddressBook
    function isRegisteredForPeriod(uint32, EpochData calldata epoch, address account)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bool)
    {
        bytes32 epochId = _computeEpochId(epoch.action);
        return _epochAddressRegistered[epochId][account];
    }

    /// @inheritdoc IAddressBook
    function getCurrentPeriod() external view virtual onlyProxy onlyInitialized returns (uint32) {
        return _getCurrentPeriod();
    }

    /// @inheritdoc IAddressBook
    function computeEpochId(uint32, EpochData calldata epoch) external pure virtual returns (bytes32) {
        return _computeEpochId(epoch.action);
    }

    /// @inheritdoc IAddressBook
    function computeSignal(uint32, EpochData calldata, address account)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (string memory)
    {
        return _computeSignal(account);
    }

    /// @inheritdoc IAddressBook
    function computeSignalHash(uint32, EpochData calldata, address account)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return _computeSignalHash(account);
    }

    /// @inheritdoc IAddressBook
    function getWorldIDVerifier() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_worldIDVerifier);
    }

    /// @inheritdoc IAddressBook
    function getPeriodStartTimestamp() external view virtual onlyProxy onlyInitialized returns (uint64) {
        return _periodStartTimestamp;
    }

    /// @inheritdoc IAddressBook
    function getPeriodLengthSeconds() external view virtual onlyProxy onlyInitialized returns (uint64) {
        return _periodLengthSeconds;
    }

    /// @inheritdoc IAddressBook
    function getEnforceCurrentOrNextPeriod() external view virtual onlyProxy onlyInitialized returns (bool) {
        return _enforceCurrentOrNextPeriod;
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IAddressBook
    function updateWorldIDVerifier(address newWorldIDVerifier) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newWorldIDVerifier == address(0)) revert ZeroAddress();

        address oldWorldIDVerifier = address(_worldIDVerifier);
        _worldIDVerifier = IWorldIDVerifier(newWorldIDVerifier);

        emit WorldIDVerifierUpdated(oldWorldIDVerifier, newWorldIDVerifier);
    }

    /// @inheritdoc IAddressBook
    function setEnforceCurrentOrNextPeriod(bool enabled) external virtual onlyOwner onlyProxy onlyInitialized {
        bool oldValue = _enforceCurrentOrNextPeriod;
        _enforceCurrentOrNextPeriod = enabled;

        emit EnforceCurrentOrNextPeriodUpdated(oldValue, enabled);
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    function _register(address account, uint32 targetPeriod, EpochData calldata epoch, RegistrationProof calldata proof)
        internal
        virtual
    {
        uint32 currentPeriod = _getCurrentPeriod();

        if (_enforceCurrentOrNextPeriod) {
            // Compare "next period" in uint256 space to avoid uint32 overflow when currentPeriod == type(uint32).max.
            bool isCurrentPeriod = targetPeriod == currentPeriod;
            bool isNextPeriod = uint256(targetPeriod) == uint256(currentPeriod) + 1;
            if (!isCurrentPeriod && !isNextPeriod) {
                revert InvalidTargetPeriod(targetPeriod, currentPeriod);
            }
        }

        uint256 epochPeriodEnd =
            uint256(_periodStartTimestamp) + (uint256(targetPeriod) + 1) * uint256(_periodLengthSeconds);
        if (uint256(proof.expiresAtMin) < epochPeriodEnd) {
            revert ExpirationBeforeEpochEnd(proof.expiresAtMin, epochPeriodEnd);
        }

        bytes32 epochId = _computeEpochId(epoch.action);

        if (_epochNullifierUsed[epochId][proof.nullifier]) {
            revert NullifierAlreadyUsed(proof.nullifier, epochId);
        }

        if (_epochAddressRegistered[epochId][account]) {
            revert AddressAlreadyRegistered(account, epochId);
        }

        uint256 signalHash = _computeSignalHash(account);

        _worldIDVerifier.verify(
            proof.nullifier,
            epoch.action,
            proof.rpId,
            proof.nonce,
            signalHash,
            proof.expiresAtMin,
            proof.issuerSchemaId,
            proof.credentialGenesisIssuedAtMin,
            proof.zeroKnowledgeProof
        );

        _epochNullifierUsed[epochId][proof.nullifier] = true;
        _epochAddressRegistered[epochId][account] = true;

        emit AddressRegistered(epochId, targetPeriod, epoch.action, account, proof.nullifier);
    }

    function _getCurrentPeriod() internal view virtual returns (uint32) {
        if (block.timestamp < _periodStartTimestamp) revert PeriodNotStarted();

        uint256 period = (block.timestamp - _periodStartTimestamp) / _periodLengthSeconds;
        if (period > type(uint32).max) revert PeriodOutOfRange();

        return uint32(period);
    }

    function _computeEpochId(uint256 action) internal pure virtual returns (bytes32) {
        return bytes32(action);
    }

    function _computeSignalHash(address account) internal pure virtual returns (uint256) {
        // Match the authenticator pipeline, which hashes UTF-8 signal bytes.
        string memory signal = _computeSignal(account);
        return uint256(keccak256(bytes(signal))) >> 8;
    }

    function _computeSignal(address account) internal pure virtual returns (string memory) {
        return Strings.toHexString(uint256(uint160(account)), 20);
    }
}
