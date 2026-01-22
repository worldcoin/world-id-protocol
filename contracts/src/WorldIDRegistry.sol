// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BinaryIMT, BinaryIMTData} from "./libraries/BinaryIMT.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {PackedAccountData} from "./libraries/PackedAccountData.sol";
import {IWorldIDRegistry} from "./interfaces/IWorldIDRegistry.sol";

/**
 * @title WorldIDRegistry
 * @author World Contributors
 * @dev The registry of World IDs. Each World ID is represented as a leaf in the Merkle tree.
 */
contract WorldIDRegistry is
    Initializable,
    EIP712Upgradeable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable,
    IWorldIDRegistry
{
    using BinaryIMT for BinaryIMTData;

    modifier onlyInitialized() {
        _onlyInitialized();
        _;
    }

    function _onlyInitialized() internal view {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
    }

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // leafIndex -> [96 bits pubkeyId bitmap][160 bits recoveryAddress]
    // Note that while 96 bits are reserved for the pubkeyId bitmap, only `maxAuthenticators` bits are used in practice.
    mapping(uint256 => uint256) internal _leafIndexToRecoveryAddressPacked;

    // authenticatorAddress -> `PackedAccountData`
    mapping(address => uint256) internal authenticatorAddressToPackedAccountData;

    // leafIndex -> nonce, used to prevent replays
    mapping(uint256 => uint256) internal leafIndexToSignatureNonce;

    // leafIndex -> recoveryCounter
    mapping(uint256 => uint256) internal leafIndexToRecoveryCounter;

    BinaryIMTData internal tree;
    uint256 internal nextLeafIndex;
    uint256 internal treeDepth;
    uint256 internal maxAuthenticators;

    // Root history tracking
    mapping(uint256 => uint256) internal rootToTimestamp;
    uint256 internal latestRoot;
    uint256 internal rootValidityWindow;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    bytes32 public constant UPDATE_AUTHENTICATOR_TYPEHASH = keccak256(
        "UpdateAuthenticator(uint256 leafIndex,address oldAuthenticatorAddress,address newAuthenticatorAddress,uint32 pubkeyId,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant INSERT_AUTHENTICATOR_TYPEHASH = keccak256(
        "InsertAuthenticator(uint256 leafIndex,address newAuthenticatorAddress,uint32 pubkeyId,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant REMOVE_AUTHENTICATOR_TYPEHASH = keccak256(
        "RemoveAuthenticator(uint256 leafIndex,address authenticatorAddress,uint32 pubkeyId,uint256 authenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant RECOVER_ACCOUNT_TYPEHASH = keccak256(
        "RecoverAccount(uint256 leafIndex,address newAuthenticatorAddress,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant UPDATE_RECOVERY_ADDRESS_TYPEHASH =
        keccak256("UpdateRecoveryAddress(uint256 leafIndex,address newRecoveryAddress,uint256 nonce)");

    string public constant EIP712_NAME = "WorldIDRegistry";
    string public constant EIP712_VERSION = "1.0";

    /// @notice Maximum allowed value for maxAuthenticators (limited by pubkey bitmap size)
    uint256 public constant MAX_AUTHENTICATORS_HARD_LIMIT = 160;

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
     */
    function initialize(uint256 initialTreeDepth) public virtual initializer {
        __EIP712_init(EIP712_NAME, EIP712_VERSION);
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        treeDepth = initialTreeDepth;
        tree.initWithDefaultZeroes(treeDepth);

        // Insert the initial leaf to start leaf indexes at 1
        // The 0-index of the tree is RESERVED.
        tree.insert(uint256(0));
        nextLeafIndex = 1;
        _recordCurrentRoot();

        maxAuthenticators = 7;
        rootValidityWindow = 3600;
    }

    ////////////////////////////////////////////////////////////
    //                  Public View Functions                 //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Returns the domain separator for the EIP712 structs.
     */
    function domainSeparatorV4() public view virtual onlyProxy onlyInitialized returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Returns the current tree root.
     */
    function currentRoot() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return tree.root;
    }

    /**
     * @dev Returns the recovery address for the given World ID (based on its leaf index).
     * @param leafIndex The index of the leaf.
     */
    function getRecoveryAddress(uint256 leafIndex) external view virtual onlyProxy onlyInitialized returns (address) {
        return _getRecoveryAddress(leafIndex);
    }

    /**
     * @dev Checks whether `root` is known and not expired according to `rootValidityWindow`.
     */
    function isValidRoot(uint256 root) external view virtual onlyProxy onlyInitialized returns (bool) {
        // The latest root is always valid.
        if (root == latestRoot) return true;
        // Check if the root is known and not expired
        uint256 ts = rootToTimestamp[root];
        if (ts == 0) return false;
        if (rootValidityWindow == 0) return true;
        return block.timestamp <= ts + rootValidityWindow;
    }

    /**
     * @dev Returns the packed account data for an authenticator address.
     * @param authenticatorAddress The authenticator address to query.
     */
    function getPackedAccountData(address authenticatorAddress)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return authenticatorAddressToPackedAccountData[authenticatorAddress];
    }

    /**
     * @dev Returns the signature nonce for a leaf index.
     * @param leafIndex The leaf index to query.
     */
    function getSignatureNonce(uint256 leafIndex) external view virtual onlyProxy onlyInitialized returns (uint256) {
        return leafIndexToSignatureNonce[leafIndex];
    }

    /**
     * @dev Returns the recovery counter for a leaf index.
     * @param leafIndex The leaf index to query.
     */
    function getRecoveryCounter(uint256 leafIndex) external view virtual onlyProxy onlyInitialized returns (uint256) {
        return leafIndexToRecoveryCounter[leafIndex];
    }

    /**
     * @dev Returns the next available leaf index.
     */
    function getNextLeafIndex() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return nextLeafIndex;
    }

    /**
     * @dev Returns the depth of the Merkle tree.
     */
    function getTreeDepth() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return treeDepth;
    }

    /**
     * @dev Returns the maximum number of authenticators allowed per account.
     */
    function getMaxAuthenticators() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return maxAuthenticators;
    }

    /**
     * @dev Returns the timestamp when a root was recorded.
     * @param root The root to query.
     */
    function getRootTimestamp(uint256 root) external view virtual onlyProxy onlyInitialized returns (uint256) {
        return rootToTimestamp[root];
    }

    /**
     * @dev Returns the latest root.
     */
    function getLatestRoot() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return latestRoot;
    }

    /**
     * @dev Returns the root validity window in seconds.
     */
    function getRootValidityWindow() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return rootValidityWindow;
    }

    ////////////////////////////////////////////////////////////
    //              Internal View Helper Functions            //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Helper function to get recovery address from the packed storage.
     */
    function _getRecoveryAddress(uint256 leafIndex) internal view returns (address) {
        return address(uint160(_leafIndexToRecoveryAddressPacked[leafIndex]));
    }

    /**
     * @dev Helper function to get pubkey bitmap from the packed storage.
     */
    function _getPubkeyBitmap(uint256 leafIndex) internal view returns (uint256) {
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
        packedAccountData = authenticatorAddressToPackedAccountData[signer];
        if (packedAccountData == 0) {
            revert AuthenticatorDoesNotExist(signer);
        }
        uint256 leafIndex = PackedAccountData.leafIndex(packedAccountData);
        uint256 actualRecoveryCounter = PackedAccountData.recoveryCounter(packedAccountData);
        uint256 expectedRecoveryCounter = leafIndexToRecoveryCounter[leafIndex];
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
        uint256 packedAccountData = authenticatorAddressToPackedAccountData[newAuthenticatorAddress];
        // If the authenticatorAddress is non-zero, we could permit it to be used if the recovery counter is less than the
        // leafIndex's recovery counter. This means the account was recovered and the authenticator address is no longer in use.
        if (packedAccountData != 0) {
            uint256 existingLeafIndex = PackedAccountData.leafIndex(packedAccountData);
            uint256 existingRecoveryCounter = PackedAccountData.recoveryCounter(packedAccountData);
            if (existingRecoveryCounter >= leafIndexToRecoveryCounter[existingLeafIndex]) {
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
     */
    function _setPubkeyBitmap(uint256 leafIndex, uint256 bitmap) internal {
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
     */
    function _setRecoveryAddressAndBitmap(uint256 leafIndex, address recoveryAddress, uint256 bitmap) internal {
        if (bitmap >> 96 != 0) {
            revert BitmapOverflow();
        }
        _leafIndexToRecoveryAddressPacked[leafIndex] = uint256(uint160(recoveryAddress)) | (bitmap << 160);
    }

    /**
     * @dev Records the current tree root.
     */
    function _recordCurrentRoot() internal virtual {
        uint256 root = tree.root;
        rootToTimestamp[root] = block.timestamp;
        latestRoot = root;
        emit RootRecorded(root, block.timestamp);
    }

    /**
     * @dev Updates a leaf in the tree and records the new root.
     */
    function _updateLeafAndRecord(
        uint256 leafIndex,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        uint256[] calldata siblingNodes
    ) internal virtual {
        tree.update(leafIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        _recordCurrentRoot();
    }

    /**
     * @dev Internal function to register an account.
     */
    function _registerAccount(
        address recoveryAddress,
        address[] calldata authenticatorAddresses,
        uint256[] calldata authenticatorPubkeys,
        uint256 offchainSignerCommitment
    ) internal virtual {
        if (authenticatorAddresses.length > maxAuthenticators) {
            revert PubkeyIdOutOfBounds();
        }
        if (authenticatorAddresses.length == 0) {
            revert EmptyAddressArray();
        }
        if (authenticatorAddresses.length != authenticatorPubkeys.length) {
            revert MismatchingArrayLengths();
        }

        uint256 leafIndex = nextLeafIndex;

        uint256 bitmap = 0;
        for (uint32 i = 0; i < authenticatorAddresses.length; i++) {
            address authenticatorAddress = authenticatorAddresses[i];
            if (authenticatorAddress == address(0)) {
                revert ZeroAddress();
            }

            _validateNewAuthenticatorAddress(authenticatorAddress);
            authenticatorAddressToPackedAccountData[authenticatorAddress] = PackedAccountData.pack(leafIndex, 0, i);
            bitmap = bitmap | (1 << i);
        }
        _setRecoveryAddressAndBitmap(leafIndex, recoveryAddress, bitmap);

        emit AccountCreated(
            leafIndex, recoveryAddress, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitment
        );

        nextLeafIndex = leafIndex + 1;
    }

    ////////////////////////////////////////////////////////////
    //         Public State-Changing Functions                //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Creates a new World ID account.
     * @param recoveryAddress The address of the recovery signer.
     * @param authenticatorAddresses The addresses of the authenticators.
     * @param offchainSignerCommitment The offchain signer commitment.
     */
    function createAccount(
        address recoveryAddress,
        address[] calldata authenticatorAddresses,
        uint256[] calldata authenticatorPubkeys,
        uint256 offchainSignerCommitment
    ) external virtual onlyProxy onlyInitialized {
        _registerAccount(recoveryAddress, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitment);
        tree.insert(offchainSignerCommitment);
        _recordCurrentRoot();
    }

    /**
     * @dev Creates multiple World ID accounts.
     * @param recoveryAddresses The addresses of the recovery signers.
     * @param authenticatorAddresses The addresses of the authenticators.
     * @param offchainSignerCommitments The offchain signer commitments.
     */
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

        for (uint256 i = 0; i < recoveryAddresses.length; i++) {
            _registerAccount(
                recoveryAddresses[i], authenticatorAddresses[i], authenticatorPubkeys[i], offchainSignerCommitments[i]
            );
        }

        // Update tree
        tree.insertMany(offchainSignerCommitments);
        _recordCurrentRoot();
    }

    /**
     * @dev Updates an existing Authenticator.
     * @param oldAuthenticatorAddress The authenticator address to update.
     * @param newAuthenticatorAddress The new authenticator address.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function updateAuthenticator(
        uint256 leafIndex,
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
        if (leafIndex == 0 || nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        _validateNewAuthenticatorAddress(newAuthenticatorAddress);
        if (oldAuthenticatorAddress == newAuthenticatorAddress) {
            revert ReusedAuthenticatorAddress();
        }
        if (pubkeyId >= maxAuthenticators) {
            revert PubkeyIdOutOfBounds();
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
        uint256 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }
        if (signer != oldAuthenticatorAddress) {
            revert MismatchedAuthenticatorSigner(oldAuthenticatorAddress, signer);
        }

        uint256 expectedNonce = leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        leafIndexToSignatureNonce[leafIndex]++;

        uint256 actualPubkeyId = PackedAccountData.pubkeyId(packedAccountData);
        if (actualPubkeyId != pubkeyId) {
            revert MismatchedPubkeyId(pubkeyId, actualPubkeyId);
        }
        uint256 bitmap = _getPubkeyBitmap(leafIndex);
        if ((bitmap & (1 << pubkeyId)) == 0) {
            revert PubkeyIdDoesNotExist();
        }

        // Delete the old authenticator
        delete authenticatorAddressToPackedAccountData[oldAuthenticatorAddress];

        // Add the new authenticator
        authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(leafIndex, uint32(leafIndexToRecoveryCounter[leafIndex]), pubkeyId);

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

    /**
     * @dev Inserts a new Authenticator.
     * @param newAuthenticatorAddress The authenticator address to insert.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function insertAuthenticator(
        uint256 leafIndex,
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

        if (pubkeyId >= maxAuthenticators) {
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
        uint256 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }

        uint256 expectedNonce = leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        leafIndexToSignatureNonce[leafIndex]++;

        // Add new authenticator
        authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(leafIndex, uint32(leafIndexToRecoveryCounter[leafIndex]), pubkeyId);
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

    /**
     * @dev Removes an Authenticator.
     * @param authenticatorAddress The authenticator address to remove.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function removeAuthenticator(
        uint256 leafIndex,
        address authenticatorAddress,
        uint32 pubkeyId,
        uint256 authenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (pubkeyId >= maxAuthenticators) {
            revert PubkeyIdOutOfBounds();
        }

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
        uint256 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }

        uint256 expectedNonce = leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        leafIndexToSignatureNonce[leafIndex]++;

        uint256 packedToRemove = authenticatorAddressToPackedAccountData[authenticatorAddress];
        if (packedToRemove == 0) {
            revert AuthenticatorDoesNotExist(authenticatorAddress);
        }
        uint256 actualLeafIndex = PackedAccountData.leafIndex(packedToRemove);
        if (actualLeafIndex != leafIndex) {
            revert AuthenticatorDoesNotBelongToAccount(leafIndex, actualLeafIndex);
        }
        uint256 actualPubkeyId = PackedAccountData.pubkeyId(packedToRemove);
        if (actualPubkeyId != pubkeyId) {
            revert MismatchedPubkeyId(pubkeyId, actualPubkeyId);
        }

        // Delete authenticator
        delete authenticatorAddressToPackedAccountData[authenticatorAddress];
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

    /**
     * @dev Recovers a World ID.
     * @param leafIndex The index of the leaf.
     * @param newAuthenticatorAddress The new authenticator address.
     * @param newAuthenticatorPubkey The new authenticator pubkey.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     * @param nonce The signature nonce.
     */
    function recoverAccount(
        uint256 leafIndex,
        address newAuthenticatorAddress,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (leafIndex == 0 || nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        uint256 expectedNonce = leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        leafIndexToSignatureNonce[leafIndex]++;

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

        leafIndexToRecoveryCounter[leafIndex]++;

        authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(leafIndex, uint32(leafIndexToRecoveryCounter[leafIndex]), uint32(0));
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

    /**
     * @dev Updates the recovery address for a World ID.
     * @param leafIndex The index of the leaf.
     * @param newRecoveryAddress The new recovery address.
     * @param signature The signature authorizing the change.
     * @param nonce The signature nonce.
     */
    function updateRecoveryAddress(uint256 leafIndex, address newRecoveryAddress, bytes memory signature, uint256 nonce)
        external
        virtual
        onlyProxy
        onlyInitialized
    {
        if (leafIndex == 0 || nextLeafIndex <= leafIndex) {
            revert AccountDoesNotExist(leafIndex);
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(UPDATE_RECOVERY_ADDRESS_TYPEHASH, leafIndex, newRecoveryAddress, nonce))
        );

        (, uint256 packedAccountData) = _recoverAccountDataFromSignature(messageHash, signature);
        uint256 recoveredLeafIndex = PackedAccountData.leafIndex(packedAccountData);
        if (leafIndex != recoveredLeafIndex) {
            revert MismatchedLeafIndex(leafIndex, recoveredLeafIndex);
        }

        uint256 expectedNonce = leafIndexToSignatureNonce[leafIndex];
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(leafIndex, expectedNonce, nonce);
        }
        leafIndexToSignatureNonce[leafIndex]++;

        address oldRecoveryAddress = _getRecoveryAddress(leafIndex);

        // Preserve the bitmap when updating the recovery address
        uint256 bitmap = _getPubkeyBitmap(leafIndex);
        _setRecoveryAddressAndBitmap(leafIndex, newRecoveryAddress, bitmap);

        emit RecoveryAddressUpdated(leafIndex, oldRecoveryAddress, newRecoveryAddress);
    }

    ////////////////////////////////////////////////////////////
    //                      Owner Functions                   //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Sets the validity window for historic roots. 0 means roots never expire.
     */
    function setRootValidityWindow(uint256 newWindow) external onlyOwner onlyProxy onlyInitialized {
        uint256 old = rootValidityWindow;
        rootValidityWindow = newWindow;
        emit RootValidityWindowUpdated(old, newWindow);
    }

    /**
     * @dev Set an updated maximum number of authenticators allowed.
     */
    function setMaxAuthenticators(uint256 newMaxAuthenticators) external onlyOwner onlyProxy onlyInitialized {
        if (newMaxAuthenticators >= MAX_AUTHENTICATORS_HARD_LIMIT) {
            revert OwnerMaxAuthenticatorsOutOfBounds();
        }
        uint256 old = maxAuthenticators;
        maxAuthenticators = newMaxAuthenticators;
        emit MaxAuthenticatorsUpdated(old, maxAuthenticators);
    }

    ////////////////////////////////////////////////////////////
    //                    Upgrade Authorization               //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Authorize upgrade to a new implementation
     * @param newImplementation Address of the new implementation contract
     * @notice Only the contract owner can authorize upgrades
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    ////////////////////////////////////////////////////////////
    //                    Storage Gap                         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Storage gap to allow for future upgrades without storage collisions
     * This reserves 50 storage slots for future state variables
     */
    uint256[50] private __gap;
}
