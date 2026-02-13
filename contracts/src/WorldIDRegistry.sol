// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BinaryIMT, BinaryIMTData} from "./libraries/BinaryIMT.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {PackedAccountData} from "./libraries/PackedAccountData.sol";
import {IWorldIDRegistry} from "./interfaces/IWorldIDRegistry.sol";
import {WorldIDBase} from "./abstract/WorldIDBase.sol";

/**
 * @title WorldIDRegistry
 * @author World Contributors
 * @notice Registry of World IDs. Each World ID is represented as a leaf in a Merkle tree.
 * @dev Manages World IDs and the authenticators which are authorized to perform operations on behalf of them.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDRegistry is WorldIDBase, IWorldIDRegistry {
    using BinaryIMT for BinaryIMTData;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev leafIndex -> [96 bits pubkeyId bitmap][160 bits recoveryAddress]
    /// Note that while 96 bits are reserved for the pubkeyId bitmap, only `_maxAuthenticators` bits are used in practice.
    mapping(uint64 => uint256) internal _leafIndexToRecoveryAddressPacked;

    /// @dev authenticatorAddress -> packed account data (leafIndex, recoveryCounter, pubkeyId)
    mapping(address => uint256) internal _authenticatorAddressToPackedAccountData;

    /// @dev leafIndex -> signature nonce for replay protection
    mapping(uint64 => uint256) internal _leafIndexToSignatureNonce;

    /// @dev leafIndex -> recovery counter (incremented on each recovery)
    mapping(uint64 => uint256) internal _leafIndexToRecoveryCounter;

    /// @dev Binary Merkle tree storing account commitments
    BinaryIMTData internal _tree;

    /// @dev Next available leaf index for new accounts
    uint64 internal _nextLeafIndex;

    /// @dev Depth of the Merkle tree
    uint256 internal _treeDepth;

    /// @dev Maximum number of authenticators per account
    uint256 internal _maxAuthenticators;

    /// @dev root -> timestamp when the root was recorded
    mapping(uint256 => uint256) internal _rootToTimestamp;

    /// @dev The most recent Merkle root
    uint256 internal _latestRoot;

    /// @dev Duration (seconds) for which historical roots remain valid
    uint256 internal _rootValidityWindow;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    bytes32 public constant UPDATE_AUTHENTICATOR_TYPEHASH = keccak256(
        "UpdateAuthenticator(uint64 leafIndex,address oldAuthenticatorAddress,address newAuthenticatorAddress,uint32 pubkeyId,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant INSERT_AUTHENTICATOR_TYPEHASH = keccak256(
        "InsertAuthenticator(uint64 leafIndex,address newAuthenticatorAddress,uint32 pubkeyId,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant REMOVE_AUTHENTICATOR_TYPEHASH = keccak256(
        "RemoveAuthenticator(uint64 leafIndex,address authenticatorAddress,uint32 pubkeyId,uint256 authenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant RECOVER_ACCOUNT_TYPEHASH = keccak256(
        "RecoverAccount(uint64 leafIndex,address newAuthenticatorAddress,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant UPDATE_RECOVERY_ADDRESS_TYPEHASH =
        keccak256("UpdateRecoveryAddress(uint64 leafIndex,address newRecoveryAddress,uint256 nonce)");

    string public constant EIP712_NAME = "WorldIDRegistry";
    string public constant EIP712_VERSION = "1.0";

    /// @notice Maximum allowed value for _maxAuthenticators (limited by pubkey bitmap size)
    uint256 public constant MAX_AUTHENTICATORS_HARD_LIMIT = 96;

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract.
     * @param initialTreeDepth The depth of the Merkle tree.
     * @param feeRecipient The recipient of registration fees (can be address(0) if no fees).
     * @param feeToken The token used to pay registration fees (can be address(0) if no fees).
     * @param registrationFee The fee to register a World ID (default: 0).
     */
    function initialize(uint256 initialTreeDepth, address feeRecipient, address feeToken, uint256 registrationFee)
        public
        virtual
        initializer
    {
        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, feeRecipient, feeToken, registrationFee);

        _treeDepth = initialTreeDepth;
        _tree.initWithDefaultZeroes(_treeDepth);

        // Insert the initial leaf to start leaf indexes at 1
        // The 0-index of the tree is RESERVED.
        _tree.insert(uint256(0));
        _nextLeafIndex = 1;
        _recordCurrentRoot();

        _maxAuthenticators = 7;
        _rootValidityWindow = 3600;
    }

    ////////////////////////////////////////////////////////////
    //                  Public View Functions                 //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDRegistry
    function domainSeparatorV4() public view virtual onlyProxy onlyInitialized returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @inheritdoc IWorldIDRegistry
    function currentRoot() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _tree.root;
    }

    /// @inheritdoc IWorldIDRegistry
    function getRecoveryAddress(uint64 leafIndex) external view virtual onlyProxy onlyInitialized returns (address) {
        return _getRecoveryAddress(leafIndex);
    }

    /// @inheritdoc IWorldIDRegistry
    function isValidRoot(uint256 root) external view virtual onlyProxy onlyInitialized returns (bool) {
        // The latest root is always valid.
        if (root == _latestRoot) return true;
        // Check if the root is known and not expired
        uint256 ts = _rootToTimestamp[root];
        if (ts == 0) return false;
        return block.timestamp <= ts + _rootValidityWindow;
    }

    /// @inheritdoc IWorldIDRegistry
    function getPackedAccountData(address authenticatorAddress)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return _authenticatorAddressToPackedAccountData[authenticatorAddress];
    }

    /// @inheritdoc IWorldIDRegistry
    function getSignatureNonce(uint64 leafIndex) external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _leafIndexToSignatureNonce[leafIndex];
    }

    /// @inheritdoc IWorldIDRegistry
    function getRecoveryCounter(uint64 leafIndex) external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _leafIndexToRecoveryCounter[leafIndex];
    }

    /// @inheritdoc IWorldIDRegistry
    function getNextLeafIndex() external view virtual onlyProxy onlyInitialized returns (uint64) {
        return _nextLeafIndex;
    }

    /// @inheritdoc IWorldIDRegistry
    function getTreeDepth() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _treeDepth;
    }

    /// @inheritdoc IWorldIDRegistry
    function getMaxAuthenticators() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _maxAuthenticators;
    }

    /// @inheritdoc IWorldIDRegistry
    function getRootTimestamp(uint256 root) external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _rootToTimestamp[root];
    }

    /// @inheritdoc IWorldIDRegistry
    function getLatestRoot() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _latestRoot;
    }

    /// @inheritdoc IWorldIDRegistry
    function getRootValidityWindow() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _rootValidityWindow;
    }

    ////////////////////////////////////////////////////////////
    //              Internal View Helper Functions            //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Helper function to get recovery address from the packed storage.
     * @param leafIndex The leaf index of the account.
     * @return The recovery address for the account.
     */
    function _getRecoveryAddress(uint64 leafIndex) internal view returns (address) {
        return address(uint160(_leafIndexToRecoveryAddressPacked[leafIndex]));
    }

    /**
     * @dev Helper function to get pubkey bitmap from the packed storage.
     * @param leafIndex The leaf index of the account.
     * @return The pubkey bitmap for the account.
     */
    function _getPubkeyBitmap(uint64 leafIndex) internal view returns (uint256) {
        return _leafIndexToRecoveryAddressPacked[leafIndex] >> 160;
    }

    /**
     * @dev Recovers the packed authenticator metadata for the signer of `messageHash`.
     * @param messageHash The message hash.
     * @param signature The signature.
     * @return signer Address recovered from the signature.
     * @return packedAccountData Packed authenticator data for the signer.
     */
    function _recoverAccountDataFromSignature(bytes32 messageHash, bytes memory signature)
        internal
        view
        virtual
        returns (address signer, uint256 packedAccountData)
    {
        signer = ECDSA.recover(messageHash, signature);
        if (signer == address(0)) {
            revert ZeroRecoveredSignatureAddress();
        }
        packedAccountData = _authenticatorAddressToPackedAccountData[signer];
        if (packedAccountData == 0) {
            revert AuthenticatorDoesNotExist(signer);
        }
        uint64 leafIndex = PackedAccountData.leafIndex(packedAccountData);
        uint256 actualRecoveryCounter = PackedAccountData.recoveryCounter(packedAccountData);
        uint256 expectedRecoveryCounter = _leafIndexToRecoveryCounter[leafIndex];
        if (actualRecoveryCounter != expectedRecoveryCounter) {
            revert MismatchedRecoveryCounter(leafIndex, expectedRecoveryCounter, actualRecoveryCounter);
        }
    }

    /**
     * @dev Validates that a new authenticator address is valid (not zero) and not in use, or if it was previously used,
     * the account has been recovered (recovery counter increased), making the address available again.
     * @param newAuthenticatorAddress The new authenticator address to validate.
     */
    function _validateNewAuthenticatorAddress(address newAuthenticatorAddress) internal view {
        if (newAuthenticatorAddress == address(0)) {
            revert ZeroAddress();
        }
        uint256 packedAccountData = _authenticatorAddressToPackedAccountData[newAuthenticatorAddress];
        // If the authenticatorAddress is non-zero, we could permit it to be used if the recovery counter is less than the
        // leafIndex's recovery counter. This means the account was recovered and the authenticator address is no longer in use.
        if (packedAccountData != 0) {
            uint64 existingLeafIndex = PackedAccountData.leafIndex(packedAccountData);
            uint256 existingRecoveryCounter = PackedAccountData.recoveryCounter(packedAccountData);
            if (existingRecoveryCounter >= _leafIndexToRecoveryCounter[existingLeafIndex]) {
                revert AuthenticatorAddressAlreadyInUse(newAuthenticatorAddress);
            }
        }
    }

    ////////////////////////////////////////////////////////////
    //       Internal State-Changing Helper Functions         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Helper function to set pubkey bitmap packed, preserving the recovery address. The
     * bitmap is 96 bits, but 256 are accepted to simplify bit operations in other functions.
     * @param leafIndex The leaf index of the account.
     * @param bitmap The new pubkey bitmap to set.
     */
    function _setPubkeyBitmap(uint64 leafIndex, uint256 bitmap) internal {
        if (bitmap >> 96 != 0) {
            revert BitmapOverflow();
        }

        uint256 packed = _leafIndexToRecoveryAddressPacked[leafIndex];
        // Clear bitmap bits and set new bitmap
        packed = (packed & uint256(type(uint160).max)) | (bitmap << 160);
        _leafIndexToRecoveryAddressPacked[leafIndex] = packed;
    }

    /**
     * @dev Helper function to set recovery address and pubkey bitmap packed. The
     * bitmap is 96 bits, but 256 are accepted to simplify bit operations in other functions.
     * @param leafIndex The leaf index of the account.
     * @param recoveryAddress The recovery address to set.
     * @param bitmap The pubkey bitmap to set.
     */
    function _setRecoveryAddressAndBitmap(uint64 leafIndex, address recoveryAddress, uint256 bitmap) internal {
        if (bitmap >> 96 != 0) {
            revert BitmapOverflow();
        }
        _leafIndexToRecoveryAddressPacked[leafIndex] = uint256(uint160(recoveryAddress)) | (bitmap << 160);
    }

    /**
     * @dev Records the current tree root.
     */
    function _recordCurrentRoot() internal virtual {
        uint256 root = _tree.root;
        _rootToTimestamp[root] = block.timestamp;
        _latestRoot = root;
        emit RootRecorded(root, block.timestamp);
    }

    /**
     * @dev Updates a leaf in the tree and records the new root.
     * @param leafIndex The leaf index to update.
     * @param oldOffchainSignerCommitment The old offchain signer commitment (current leaf value).
     * @param newOffchainSignerCommitment The new offchain signer commitment (new leaf value).
     * @param siblingNodes The Merkle proof sibling nodes.
     */
    function _updateLeafAndRecord(
        uint64 leafIndex,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        uint256[] calldata siblingNodes
    ) internal virtual {
        _tree.update(uint256(leafIndex), oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        _recordCurrentRoot();
    }

    /**
     * @dev Internal function to register an account.
     * @param recoveryAddress The recovery address for the new account.
     * @param authenticatorAddresses The authenticator addresses for the new account.
     * @param authenticatorPubkeys The authenticator pubkeys for the new account.
     * @param offchainSignerCommitment The offchain signer commitment for the new account.
     */
    function _registerAccount(
        address recoveryAddress,
        address[] calldata authenticatorAddresses,
        uint256[] calldata authenticatorPubkeys,
        uint256 offchainSignerCommitment
    ) internal virtual {
        // Handle fee payment if required
        _collectFee();

        if (authenticatorAddresses.length > _maxAuthenticators) {
            revert PubkeyIdOutOfBounds();
        }
        if (authenticatorAddresses.length == 0) {
            revert EmptyAddressArray();
        }
        if (authenticatorAddresses.length != authenticatorPubkeys.length) {
            revert MismatchingArrayLengths();
        }

        uint64 leafIndex = _nextLeafIndex;

        for (uint32 i = 0; i < authenticatorAddresses.length; i++) {
            address authenticatorAddress = authenticatorAddresses[i];
            if (authenticatorAddress == address(0)) {
                revert ZeroAddress();
            }

            _validateNewAuthenticatorAddress(authenticatorAddress);
            _authenticatorAddressToPackedAccountData[authenticatorAddress] = PackedAccountData.pack(leafIndex, 0, i);
        }
        uint256 bitmap = (1 << authenticatorAddresses.length) - 1;
        _setRecoveryAddressAndBitmap(leafIndex, recoveryAddress, bitmap);

        emit AccountCreated(
            leafIndex, recoveryAddress, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitment
        );

        _nextLeafIndex = leafIndex + 1;
    }

    ////////////////////////////////////////////////////////////
    //         Public State-Changing Functions                //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDRegistry
    function createAccount(
        address recoveryAddress,
        address[] calldata authenticatorAddresses,
        uint256[] calldata authenticatorPubkeys,
        uint256 offchainSignerCommitment
    ) external virtual onlyProxy onlyInitialized {
        if (_registrationFee > 0 && _feeToken.balanceOf(msg.sender) < _registrationFee) {
            revert InsufficientFunds();
        }
        _registerAccount(recoveryAddress, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitment);
        _tree.insert(offchainSignerCommitment);
        _recordCurrentRoot();
    }

    /// @inheritdoc IWorldIDRegistry
    function createManyAccounts(
        address[] calldata recoveryAddresses,
        address[][] calldata authenticatorAddresses,
        uint256[][] calldata authenticatorPubkeys,
        uint256[] calldata offchainSignerCommitments
    ) external virtual onlyProxy onlyInitialized {
        if (recoveryAddresses.length == 0) {
            revert EmptyAddressArray();
        }

        if (recoveryAddresses.length != authenticatorAddresses.length) {
            revert MismatchingArrayLengths();
        }
        if (recoveryAddresses.length != authenticatorPubkeys.length) {
            revert MismatchingArrayLengths();
        }
        if (recoveryAddresses.length != offchainSignerCommitments.length) {
            revert MismatchingArrayLengths();
        }

        if (_registrationFee > 0 && _feeToken.balanceOf(msg.sender) < recoveryAddresses.length * _registrationFee) {
            revert InsufficientFunds();
        }

        for (uint256 i = 0; i < recoveryAddresses.length; i++) {
            _registerAccount(
                recoveryAddresses[i], authenticatorAddresses[i], authenticatorPubkeys[i], offchainSignerCommitments[i]
            );
        }

        // Update tree
        _tree.insertMany(offchainSignerCommitments);
        _recordCurrentRoot();
    }

    /// @inheritdoc IWorldIDRegistry
    function updateAuthenticator(
        uint64 leafIndex,
        address oldAuthenticatorAddress,
        address newAuthenticatorAddress,
        uint32 pubkeyId,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (leafIndex == 0 || _nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        _validateNewAuthenticatorAddress(newAuthenticatorAddress);

        if (oldAuthenticatorAddress == newAuthenticatorAddress) {
            revert ReusedAuthenticatorAddress();
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    UPDATE_AUTHENTICATOR_TYPEHASH,
                    leafIndex,
                    oldAuthenticatorAddress,
                    newAuthenticatorAddress,
                    pubkeyId,
                    newAuthenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (address signer, uint256 packedAccountData) = _recoverAccountDataFromSignature(messageHash, signature);
        uint64 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }
        if (signer != oldAuthenticatorAddress) {
            revert MismatchedAuthenticatorSigner(oldAuthenticatorAddress, signer);
        }

        uint256 expectedNonce = _leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        _leafIndexToSignatureNonce[leafIndex]++;

        uint256 actualPubkeyId = PackedAccountData.pubkeyId(packedAccountData);
        if (actualPubkeyId != pubkeyId) {
            revert MismatchedPubkeyId(pubkeyId, actualPubkeyId);
        }
        uint256 bitmap = _getPubkeyBitmap(leafIndex);
        if ((bitmap & (1 << pubkeyId)) == 0) {
            revert PubkeyIdDoesNotExist();
        }

        // Delete the old authenticator
        delete _authenticatorAddressToPackedAccountData[oldAuthenticatorAddress];

        // Add the new authenticator
        if (_leafIndexToRecoveryCounter[leafIndex] > type(uint32).max) {
            revert RecoveryCounterOverflow();
        }
        _authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(leafIndex, uint32(_leafIndexToRecoveryCounter[leafIndex]), pubkeyId);

        // Update the tree
        emit AccountUpdated(
            leafIndex,
            pubkeyId,
            newAuthenticatorPubkey,
            oldAuthenticatorAddress,
            newAuthenticatorAddress,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(leafIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
    }

    /// @inheritdoc IWorldIDRegistry
    function insertAuthenticator(
        uint64 leafIndex,
        address newAuthenticatorAddress,
        uint32 pubkeyId,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        _validateNewAuthenticatorAddress(newAuthenticatorAddress);

        if (pubkeyId >= _maxAuthenticators) {
            revert PubkeyIdOutOfBounds();
        }

        uint256 bitmap = _getPubkeyBitmap(leafIndex);
        if ((bitmap & (1 << pubkeyId)) != 0) {
            revert PubkeyIdInUse();
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    INSERT_AUTHENTICATOR_TYPEHASH,
                    leafIndex,
                    newAuthenticatorAddress,
                    pubkeyId,
                    newAuthenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (, uint256 packedAccountData) = _recoverAccountDataFromSignature(messageHash, signature);
        uint64 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }

        uint256 expectedNonce = _leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        _leafIndexToSignatureNonce[leafIndex]++;

        // Add new authenticator
        if (_leafIndexToRecoveryCounter[leafIndex] > type(uint32).max) {
            revert RecoveryCounterOverflow();
        }
        _authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(leafIndex, uint32(_leafIndexToRecoveryCounter[leafIndex]), pubkeyId);
        _setPubkeyBitmap(leafIndex, bitmap | (1 << uint256(pubkeyId)));

        // Update tree
        emit AuthenticatorInserted(
            leafIndex,
            pubkeyId,
            newAuthenticatorAddress,
            newAuthenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(leafIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
    }

    /// @inheritdoc IWorldIDRegistry
    function removeAuthenticator(
        uint64 leafIndex,
        address authenticatorAddress,
        uint32 pubkeyId,
        uint256 authenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    REMOVE_AUTHENTICATOR_TYPEHASH,
                    leafIndex,
                    authenticatorAddress,
                    pubkeyId,
                    authenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (, uint256 packedAccountData) = _recoverAccountDataFromSignature(messageHash, signature);
        uint64 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }

        uint256 expectedNonce = _leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        _leafIndexToSignatureNonce[leafIndex]++;

        uint256 packedToRemove = _authenticatorAddressToPackedAccountData[authenticatorAddress];
        if (packedToRemove == 0) {
            revert AuthenticatorDoesNotExist(authenticatorAddress);
        }
        uint64 actualLeafIndex = PackedAccountData.leafIndex(packedToRemove);
        if (actualLeafIndex != leafIndex) {
            revert AuthenticatorDoesNotBelongToAccount(leafIndex, actualLeafIndex);
        }
        uint256 actualPubkeyId = PackedAccountData.pubkeyId(packedToRemove);
        if (actualPubkeyId != pubkeyId) {
            revert MismatchedPubkeyId(pubkeyId, actualPubkeyId);
        }
        uint256 actualRecoveryCounter = PackedAccountData.recoveryCounter(packedToRemove);
        uint256 expectedRecoveryCounter = _leafIndexToRecoveryCounter[leafIndex];
        if (actualRecoveryCounter != expectedRecoveryCounter) {
            revert MismatchedRecoveryCounter(leafIndex, expectedRecoveryCounter, actualRecoveryCounter);
        }

        // Delete authenticator
        delete _authenticatorAddressToPackedAccountData[authenticatorAddress];
        _setPubkeyBitmap(leafIndex, _getPubkeyBitmap(leafIndex) & ~(1 << pubkeyId));

        // Update tree
        emit AuthenticatorRemoved(
            leafIndex,
            pubkeyId,
            authenticatorAddress,
            authenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(leafIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
    }

    /// @inheritdoc IWorldIDRegistry
    function recoverAccount(
        uint64 leafIndex,
        address newAuthenticatorAddress,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (leafIndex == 0 || _nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        uint256 expectedNonce = _leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        _leafIndexToSignatureNonce[leafIndex]++;

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECOVER_ACCOUNT_TYPEHASH,
                    leafIndex,
                    newAuthenticatorAddress,
                    newAuthenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        address recoverySigner = _getRecoveryAddress(leafIndex);
        if (recoverySigner == address(0)) {
            revert RecoveryNotEnabled();
        }
        if (!SignatureChecker.isValidSignatureNow(recoverySigner, messageHash, signature)) {
            revert InvalidSignature();
        }

        _validateNewAuthenticatorAddress(newAuthenticatorAddress);

        _leafIndexToRecoveryCounter[leafIndex]++;

        if (_leafIndexToRecoveryCounter[leafIndex] > type(uint32).max) {
            revert RecoveryCounterOverflow();
        }
        _authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(leafIndex, uint32(_leafIndexToRecoveryCounter[leafIndex]), uint32(0));
        _setPubkeyBitmap(leafIndex, 1); // Reset to only pubkeyId 0

        emit AccountRecovered(
            leafIndex,
            newAuthenticatorAddress,
            newAuthenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(leafIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
    }

    /// @inheritdoc IWorldIDRegistry
    function updateRecoveryAddress(uint64 leafIndex, address newRecoveryAddress, bytes memory signature, uint256 nonce)
        external
        virtual
        onlyProxy
        onlyInitialized
    {
        if (leafIndex == 0 || _nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(UPDATE_RECOVERY_ADDRESS_TYPEHASH, leafIndex, newRecoveryAddress, nonce))
        );

        (, uint256 packedAccountData) = _recoverAccountDataFromSignature(messageHash, signature);
        uint64 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }

        uint256 expectedNonce = _leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        _leafIndexToSignatureNonce[leafIndex]++;

        address oldRecoveryAddress = _getRecoveryAddress(leafIndex);

        // Preserve the bitmap when updating the recovery address
        uint256 bitmap = _getPubkeyBitmap(leafIndex);
        _setRecoveryAddressAndBitmap(leafIndex, newRecoveryAddress, bitmap);

        emit RecoveryAddressUpdated(leafIndex, oldRecoveryAddress, newRecoveryAddress);
    }

    ////////////////////////////////////////////////////////////
    //                      Owner Functions                   //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDRegistry
    function setRootValidityWindow(uint256 newWindow) external onlyOwner onlyProxy onlyInitialized {
        uint256 old = _rootValidityWindow;
        _rootValidityWindow = newWindow;
        emit RootValidityWindowUpdated(old, newWindow);
    }

    /// @inheritdoc IWorldIDRegistry
    function setMaxAuthenticators(uint256 newMaxAuthenticators) external onlyOwner onlyProxy onlyInitialized {
        if (newMaxAuthenticators > MAX_AUTHENTICATORS_HARD_LIMIT) {
            revert OwnerMaxAuthenticatorsOutOfBounds();
        }
        uint256 old = _maxAuthenticators;
        _maxAuthenticators = newMaxAuthenticators;
        emit MaxAuthenticatorsUpdated(old, _maxAuthenticators);
    }
}
