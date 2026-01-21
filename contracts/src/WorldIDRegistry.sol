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

/**
 * @title WorldIDRegistry
 * @author World Contributors
 * @dev The registry of World IDs. Each World ID is represented as a leaf in the Merkle tree.
 */
contract WorldIDRegistry is Initializable, EIP712Upgradeable, Ownable2StepUpgradeable, UUPSUpgradeable {
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
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    /// @notice Maximum allowed value for maxAuthenticators (limited by pubkey bitmap size)
    uint256 public constant MAX_AUTHENTICATORS_LIMIT = 160;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // leafIndex -> [96 bits pubkeyId bitmap][160 bits recoveryAddress]
    // Note that while 96 bits are reserved for the pubkeyId bitmap, only `maxAuthenticators` bits are used in practice.
    mapping(uint256 => uint256) internal _leafIndexToRecoveryAddressPacked;

    // authenticatorAddress -> `PackedAccountData`
    mapping(address => uint256) public authenticatorAddressToPackedAccountData;

    // leafIndex -> nonce, used to prevent replays
    mapping(uint256 => uint256) public leafIndexToSignatureNonce;

    // leafIndex -> recoveryCounter
    mapping(uint256 => uint256) public leafIndexToRecoveryCounter;

    BinaryIMTData public tree;
    uint256 public nextLeafIndex;
    uint256 public treeDepth;
    uint256 public maxAuthenticators;

    // Root history tracking
    mapping(uint256 => uint256) public rootToTimestamp;
    uint256 public latestRoot;
    uint256 public rootValidityWindow;

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event AccountCreated(
        uint256 indexed leafIndex,
        address indexed recoveryAddress,
        address[] authenticatorAddresses,
        uint256[] authenticatorPubkeys,
        uint256 offchainSignerCommitment
    );
    event AccountUpdated(
        uint256 indexed leafIndex,
        uint32 pubkeyId,
        uint256 newAuthenticatorPubkey,
        address indexed oldAuthenticatorAddress,
        address indexed newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AccountRecovered(
        uint256 indexed leafIndex,
        address indexed newAuthenticatorAddress,
        uint256 indexed newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event RecoveryAddressUpdated(
        uint256 indexed leafIndex, address indexed oldRecoveryAddress, address indexed newRecoveryAddress
    );
    event AuthenticatorInserted(
        uint256 indexed leafIndex,
        uint32 pubkeyId,
        address indexed authenticatorAddress,
        uint256 indexed newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AuthenticatorRemoved(
        uint256 indexed leafIndex,
        uint32 pubkeyId,
        address indexed authenticatorAddress,
        uint256 indexed authenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event RootRecorded(uint256 indexed root, uint256 timestamp);
    event RootValidityWindowUpdated(uint256 oldWindow, uint256 newWindow);
    event MaxAuthenticatorsUpdated(uint256 oldMax, uint256 newMax);

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

    ////////////////////////////////////////////////////////////
    //                        Errors                         //
    ////////////////////////////////////////////////////////////

    error ImplementationNotInitialized();

    /**
     * @dev Thrown when a requested on-chain signer address is already in use by another account as an authenticator. An on-chain signer address
     * can only be used by one account at a time.
     * @param authenticatorAddress The target address that is already in use.
     */
    error AuthenticatorAddressAlreadyInUse(address authenticatorAddress);

    /**
     * @dev Thrown when the pubkey bitmap overflows, which should in practice never happen.
     */
    error BitmapOverflow();

    /**
     * @dev Thrown when the pubkey ID is already in use for the account on a different authenticator.
     */
    error PubkeyIdInUse();

    /**
     * @dev Thrown when attempting to use a pubKeyId that is greater than `maxAuthenticators`.
     */
    error PubkeyIdOutOfBounds();

    /**
     * @dev Thrown when a pubkey ID does not exist. We use a bitmap to track how many pubkey IDs are in use for an account.
     */
    error PubkeyIdDoesNotExist();

    /**
     * @dev Thrown when there is no Recovery Agent (i.e. recovery address) set for the account.
     */
    error RecoveryNotEnabled();

    /**
     * @dev Thrown when a requested leaf index does not exist.
     * @param leafIndex The leaf index that does not exist.
     */
    error AccountDoesNotExist(uint256 leafIndex);

    /**
     * @dev Thrown when a recovered signature address is the zero address.
     */
    error ZeroRecoveredSignatureAddress();

    /**
     * @dev Thrown when setting a recovery or authenticator address to the zero address.
     */
    error ZeroAddress();

    /**
     * @dev Thrown when an invalid signature is provided.
     */
    error InvalidSignature();

    /**
     * @dev Thrown when the provided array lengths do not match.
     */
    error MismatchingArrayLengths();

    /**
     * @dev Thrown when the provided address array is empty.
     */
    error EmptyAddressArray();

    /**
     * @dev Thrown when the old and new authenticator addresses are the same.
     */
    error ReusedAuthenticatorAddress();

    /**
     * @dev Thrown when an authenticator already exists.
     * @param authenticatorAddress The authenticator address that already exists.
     */
    error AuthenticatorAlreadyExists(address authenticatorAddress);

    /**
     * @dev Thrown when the leaf index does not match the expected value.
     * @param expectedLeafIndex The expected leaf index.
     * @param actualLeafIndex The actual leaf index.
     */
    error MismatchedLeafIndex(uint256 expectedLeafIndex, uint256 actualLeafIndex);

    /**
     * @dev Thrown when the recovered signature does not match the expected authenticator address.
     * @param expectedAuthenticatorAddress The expected authenticator address.
     * @param actualAuthenticatorAddress The actual authenticator address.
     */
    error MismatchedAuthenticatorSigner(address expectedAuthenticatorAddress, address actualAuthenticatorAddress);

    /**
     * @dev Thrown when a pubkey ID does not match the expected value.
     * @param expectedPubkeyId The expected pubkey ID.
     * @param actualPubkeyId The actual pubkey ID.
     */
    error MismatchedPubkeyId(uint256 expectedPubkeyId, uint256 actualPubkeyId);

    /**
     * @dev Thrown when a nonce does not match the expected value.
     * @param expectedNonce The expected nonce value.
     * @param actualNonce The actual nonce value.
     */
    error MismatchedSignatureNonce(uint256 leafIndex, uint256 expectedNonce, uint256 actualNonce);

    /**
     * @dev Thrown when a recovery counter does not match the expected value.
     * @param leafIndex The leaf index.
     * @param expectedRecoveryCounter The expected recovery counter.
     * @param actualRecoveryCounter The actual recovery counter.
     */
    error MismatchedRecoveryCounter(uint256 leafIndex, uint256 expectedRecoveryCounter, uint256 actualRecoveryCounter);

    /**
     * @dev Thrown when a pubkey ID overflows its uint32 limit.
     * @param pubkeyId The pubkey ID that caused the overflow.
     */
    error PubkeyIdOverflow(uint256 pubkeyId);

    /**
     * @dev Thrown when a recovery address is not set for an account.
     * @param leafIndex The leaf index with no recovery address.
     */
    error RecoveryAddressNotSet(uint256 leafIndex);

    /**
     * @dev Thrown when an authenticator does not exist.
     * @param authenticatorAddress The authenticator address that does not exist.
     */
    error AuthenticatorDoesNotExist(address authenticatorAddress);

    /**
     * @dev Thrown when an authenticator does not belong to the specified account.
     * @param expectedLeafIndex The expected leaf index.
     * @param actualLeafIndex The actual leaf index from the authenticator.
     */
    error AuthenticatorDoesNotBelongToAccount(uint256 expectedLeafIndex, uint256 actualLeafIndex);

    /**
     * @dev Thrown when trying to update max authenticators beyond the natural limit.
     */
    error OwnerMaxAuthenticatorsOutOfBounds();

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
    //                        Functions                       //
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
        if (newMaxAuthenticators >= MAX_AUTHENTICATORS_LIMIT) {
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
