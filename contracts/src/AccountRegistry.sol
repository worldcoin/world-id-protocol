// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BinaryIMT, BinaryIMTData} from "./tree/BinaryIMT.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {PackedAccountData} from "./lib/PackedAccountData.sol";

contract AccountRegistry is Initializable, EIP712Upgradeable, Ownable2StepUpgradeable, UUPSUpgradeable {
    using BinaryIMT for BinaryIMTData;

    modifier onlyInitialized() {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
        _;
    }

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // accountIndex -> [96 bits pubkeyId bitmap][160 bits recoveryAddress]
    // Note that while 96 bits are reserved for the pubkeyId bitmap, only MAX_AUTHENTICATORS bits are used in practice.
    mapping(uint256 => uint256) internal _accountIndexToRecoveryAddressPacked;

    // authenticatorAddress -> [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
    mapping(address => uint256) public authenticatorAddressToPackedAccountData;

    // accountIndex -> nonce, used to prevent replays
    mapping(uint256 => uint256) public accountIndexToSignatureNonce;

    // authenticatorAddressToPackedAccountData

    // accountIndex -> recoveryCounter
    mapping(uint256 => uint256) public accountIndexToRecoveryCounter;

    BinaryIMTData public tree;
    uint256 public nextAccountIndex;
    uint256 public treeDepth;

    // Root history tracking
    mapping(uint256 => uint256) public rootToTimestamp;
    uint256 public latestRoot;
    uint256 public rootValidityWindow = 3600;

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event AccountCreated(
        uint256 indexed accountIndex,
        address indexed recoveryAddress,
        address[] authenticatorAddresses,
        uint256[] authenticatorPubkeys,
        uint256 offchainSignerCommitment
    );
    event AccountUpdated(
        uint256 indexed accountIndex,
        uint32 pubkeyId,
        uint256 newAuthenticatorPubkey,
        address indexed oldAuthenticatorAddress,
        address indexed newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AccountRecovered(
        uint256 indexed accountIndex,
        address indexed newAuthenticatorAddress,
        uint256 indexed newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event RecoveryAddressUpdated(
        uint256 indexed accountIndex, address indexed oldRecoveryAddress, address indexed newRecoveryAddress
    );
    event AuthenticatorInserted(
        uint256 indexed accountIndex,
        uint32 pubkeyId,
        address indexed authenticatorAddress,
        uint256 indexed newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AuthenticatorRemoved(
        uint256 indexed accountIndex,
        uint32 pubkeyId,
        address indexed authenticatorAddress,
        uint256 indexed authenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event RootRecorded(uint256 indexed root, uint256 timestamp);
    event RootValidityWindowUpdated(uint256 oldWindow, uint256 newWindow);

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    uint256 public constant MAX_AUTHENTICATORS = 7;

    bytes32 public constant UPDATE_AUTHENTICATOR_TYPEHASH = keccak256(
        "UpdateAuthenticator(uint256 accountIndex,address oldAuthenticatorAddress,address newAuthenticatorAddress,uint32 pubkeyId,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant INSERT_AUTHENTICATOR_TYPEHASH = keccak256(
        "InsertAuthenticator(uint256 accountIndex,address newAuthenticatorAddress,uint32 pubkeyId,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant REMOVE_AUTHENTICATOR_TYPEHASH = keccak256(
        "RemoveAuthenticator(uint256 accountIndex,address authenticatorAddress,uint32 pubkeyId,uint256 authenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant RECOVER_ACCOUNT_TYPEHASH = keccak256(
        "RecoverAccount(uint256 accountIndex,address newAuthenticatorAddress,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant UPDATE_RECOVERY_ADDRESS_TYPEHASH =
        keccak256("UpdateRecoveryAddress(uint256 accountIndex,address newRecoveryAddress,uint256 nonce)");

    string public constant EIP712_NAME = "AccountRegistry";
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
     * @dev Thrown when attempting to use a pubKeyId that is greater than MAX_AUTHENTICATORS.
     */
    error PubkeyIdOutOfBounds();

    /**
     * @dev Thrown when a pubkey ID does not exist.
     */
    error PubkeyIdDoesNotExist();

    /**
     * @dev Thrown when there is no Recovery Agent (i.e. recovery address) set for the account.
     */
    error RecoveryNotEnabled();

    /**
     * @dev Thrown when a requested account index does not exist.
     * @param accountIndex The account index that does not exist.
     */
    error AccountDoesNotExist(uint256 accountIndex);

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
     * @param array1Length The length of the first array.
     * @param array2Length The length of the second array.
     */
    error MismatchingArrayLengths(uint256 array1Length, uint256 array2Length);

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
     * @dev Thrown when the account index does not match the expected value.
     * @param expectedAccountIndex The expected account index.
     * @param actualAccountIndex The actual account index.
     */
    error MismatchedAccountIndex(uint256 expectedAccountIndex, uint256 actualAccountIndex);

    /**
     * @dev Thrown when the recovered signature does match the expected authenticator address.
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
    error MismatchedSignatureNonce(uint256 accountIndex, uint256 expectedNonce, uint256 actualNonce);

    /**
     * @dev Thrown when a recovery counter does not match the expected value.
     * @param accountIndex The account index.
     * @param expectedRecoveryCounter The expected recovery counter.
     * @param actualRecoveryCounter The actual recovery counter.
     */
    error MismatchedRecoveryCounter(
        uint256 accountIndex, uint256 expectedRecoveryCounter, uint256 actualRecoveryCounter
    );

    /**
     * @dev Thrown when a pubkey ID overflows its uint32 limit.
     * @param pubkeyId The pubkey ID that caused the overflow.
     */
    error PubkeyIdOverflow(uint256 pubkeyId);

    /**
     * @dev Thrown when a recovery address is not set for an account.
     * @param accountIndex The account index with no recovery address.
     */
    error RecoveryAddressNotSet(uint256 accountIndex);

    /**
     * @dev Thrown when an authenticator does not exist.
     * @param authenticatorAddress The authenticator address that does not exist.
     */
    error AuthenticatorDoesNotExist(address authenticatorAddress);

    /**
     * @dev Thrown when an authenticator does not belong to the specified account.
     * @param expectedAccountIndex The expected account index.
     * @param actualAccountIndex The actual account index from the authenticator.
     */
    error AuthenticatorDoesNotBelongToAccount(uint256 expectedAccountIndex, uint256 actualAccountIndex);

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

        // Insert the initial leaf to start account indexes at 1
        // The 0-index of the tree is RESERVED.
        tree.insert(uint256(0));
        nextAccountIndex = 1;
        _recordCurrentRoot();
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
     * @dev Returns the recovery address for the given the account index.
     * @param accountIndex The index of the account.
     */
    function getRecoveryAddress(uint256 accountIndex)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (address)
    {
        return _getRecoveryAddress(accountIndex);
    }

    /**
     * @dev Sets the validity window for historic roots. 0 means roots never expire.
     */
    function setRootValidityWindow(uint256 newWindow) external virtual onlyOwner onlyProxy onlyInitialized {
        uint256 old = rootValidityWindow;
        rootValidityWindow = newWindow;
        emit RootValidityWindowUpdated(old, newWindow);
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
     * @dev Helper function to get recovery address from packed
     */
    function _getRecoveryAddress(uint256 accountIndex) internal view returns (address) {
        return address(uint160(_accountIndexToRecoveryAddressPacked[accountIndex]));
    }

    /**
     * @dev Helper function to get pubkey bitmap from the packed storage.
     */
    function _getPubkeyBitmap(uint256 accountIndex) internal view returns (uint256) {
        return _accountIndexToRecoveryAddressPacked[accountIndex] >> 160;
    }

    /**
     * @dev Helper function to set pubkey bitmap packed, preserving the recovery address. The
     * bitmap is 96 bits, but 256 are accepted to simplify bit operations in other functions.
     */
    function _setPubkeyBitmap(uint256 accountIndex, uint256 bitmap) internal {
        if (bitmap >> 96 != 0) {
            revert BitmapOverflow();
        }

        uint256 packed = _accountIndexToRecoveryAddressPacked[accountIndex];
        // Clear bitmap bits and set new bitmap
        packed = (packed & uint256(type(uint160).max)) | (bitmap << 160);
        _accountIndexToRecoveryAddressPacked[accountIndex] = packed;
    }

    /**
     * @dev Helper function to set recovery address and pubkey bitmap packed. The
     * bitmap is 96 bits, but 256 are accepted to simplify bit operations in other functions.
     */
    function _setRecoveryAddressAndBitmap(uint256 accountIndex, address recoveryAddress, uint256 bitmap) internal {
        if (bitmap >> 96 != 0) {
            revert BitmapOverflow();
        }
        _accountIndexToRecoveryAddressPacked[accountIndex] = uint256(uint160(recoveryAddress)) | (bitmap << 160);
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
        uint256 accountIndex,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        uint256[] calldata siblingNodes
    ) internal virtual {
        tree.update(accountIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        _recordCurrentRoot();
    }

    /**
     * @dev Recovers the packed authenticator metadata for the signer of `messageHash`.
     * @param messageHash The message hash.
     * @param signature The signature.
     * @return signer Address recovered from the signature.
     * @return packedAccountData Packed authenticator data for the signer.
     */
    function recoverAccountDataFromSignature(bytes32 messageHash, bytes memory signature)
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
            revert AccountDoesNotExist(0);
        }
        uint256 accountIndex = PackedAccountData.accountIndex(packedAccountData);
        uint256 actualRecoveryCounter = PackedAccountData.recoveryCounter(packedAccountData);
        uint256 expectedRecoveryCounter = accountIndexToRecoveryCounter[accountIndex];
        if (actualRecoveryCounter != expectedRecoveryCounter) {
            revert MismatchedRecoveryCounter(accountIndex, expectedRecoveryCounter, actualRecoveryCounter);
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
        // accountIndex's recovery counter. This means the account was recovered and the authenticator address is no longer in use.
        if (packedAccountData != 0) {
            uint256 existingAccountIndex = PackedAccountData.accountIndex(packedAccountData);
            uint256 existingRecoveryCounter = PackedAccountData.recoveryCounter(packedAccountData);
            if (existingRecoveryCounter >= accountIndexToRecoveryCounter[existingAccountIndex]) {
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
        if (authenticatorAddresses.length > MAX_AUTHENTICATORS) {
            revert PubkeyIdOutOfBounds();
        }
        if (authenticatorAddresses.length == 0) {
            revert EmptyAddressArray();
        }
        if (authenticatorAddresses.length != authenticatorPubkeys.length) {
            revert MismatchingArrayLengths(authenticatorAddresses.length, authenticatorPubkeys.length);
        }

        uint256 accountIndex = nextAccountIndex;

        uint256 bitmap = 0;
        for (uint256 i = 0; i < authenticatorAddresses.length; i++) {
            address authenticatorAddress = authenticatorAddresses[i];
            if (authenticatorAddress == address(0)) {
                revert ZeroAddress();
            }

            _validateNewAuthenticatorAddress(authenticatorAddress);
            authenticatorAddressToPackedAccountData[authenticatorAddress] =
                PackedAccountData.pack(accountIndex, 0, uint32(i));
            bitmap = bitmap | (1 << i);
        }
        _setRecoveryAddressAndBitmap(accountIndex, recoveryAddress, bitmap);

        emit AccountCreated(
            accountIndex, recoveryAddress, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitment
        );

        nextAccountIndex = accountIndex + 1;
    }

    /**
     * @dev Creates a new account.
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
     * @dev Creates multiple accounts.
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
            revert MismatchingArrayLengths(recoveryAddresses.length, authenticatorAddresses.length);
        }
        if (recoveryAddresses.length != authenticatorPubkeys.length) {
            revert MismatchingArrayLengths(recoveryAddresses.length, authenticatorPubkeys.length);
        }
        if (recoveryAddresses.length != offchainSignerCommitments.length) {
            revert MismatchingArrayLengths(recoveryAddresses.length, offchainSignerCommitments.length);
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
     * @dev Updates an existing authenticator.
     * @param oldAuthenticatorAddress The authenticator address to update.
     * @param newAuthenticatorAddress The new authenticator address.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function updateAuthenticator(
        uint256 accountIndex,
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
        if (accountIndex == 0 || nextAccountIndex <= accountIndex) {
            revert AccountDoesNotExist(accountIndex);
        }

        _validateNewAuthenticatorAddress(newAuthenticatorAddress);
        if (oldAuthenticatorAddress == newAuthenticatorAddress) {
            revert ReusedAuthenticatorAddress();
        }
        if (newAuthenticatorAddress == address(0)) {
            revert ZeroAddress();
        }
        if (pubkeyId >= MAX_AUTHENTICATORS) {
            revert PubkeyIdOutOfBounds();
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    UPDATE_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    oldAuthenticatorAddress,
                    newAuthenticatorAddress,
                    pubkeyId,
                    newAuthenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (address signer, uint256 packedAccountData) = recoverAccountDataFromSignature(messageHash, signature);
        uint256 recoveredAccountIndex = PackedAccountData.accountIndex(packedAccountData);
        if (accountIndex != recoveredAccountIndex) {
            revert MismatchedAccountIndex(accountIndex, recoveredAccountIndex);
        }
        if (signer != oldAuthenticatorAddress) {
            revert MismatchedAuthenticatorSigner(oldAuthenticatorAddress, signer);
        }
        uint256 expectedNonce = accountIndexToSignatureNonce[accountIndex]++;
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(accountIndex, expectedNonce, nonce);
        }
        uint256 actualPubkeyId = PackedAccountData.pubkeyId(packedAccountData);
        if (actualPubkeyId != pubkeyId) {
            revert MismatchedPubkeyId(pubkeyId, actualPubkeyId);
        }
        uint256 bitmap = _getPubkeyBitmap(accountIndex);
        if ((bitmap & (1 << pubkeyId)) == 0) {
            revert PubkeyIdDoesNotExist();
        }

        // Delete the old authenticator
        delete authenticatorAddressToPackedAccountData[oldAuthenticatorAddress];

        // Add the new authenticator
        authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(accountIndex, uint32(accountIndexToRecoveryCounter[accountIndex]), pubkeyId);

        // Update the tree
        emit AccountUpdated(
            accountIndex,
            pubkeyId,
            newAuthenticatorPubkey,
            oldAuthenticatorAddress,
            newAuthenticatorAddress,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(accountIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
    }

    /**
     * @dev Inserts a new authenticator.
     * @param newAuthenticatorAddress The authenticator address to insert.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function insertAuthenticator(
        uint256 accountIndex,
        address newAuthenticatorAddress,
        uint32 pubkeyId,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (newAuthenticatorAddress == address(0)) {
            revert ZeroAddress();
        }
        _validateNewAuthenticatorAddress(newAuthenticatorAddress);

        if (pubkeyId >= MAX_AUTHENTICATORS) {
            revert PubkeyIdOutOfBounds();
        }

        uint256 bitmap = _getPubkeyBitmap(accountIndex);
        if ((bitmap & (1 << pubkeyId)) != 0) {
            revert PubkeyIdInUse();
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    INSERT_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    newAuthenticatorAddress,
                    pubkeyId,
                    newAuthenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (, uint256 packedAccountData) = recoverAccountDataFromSignature(messageHash, signature);
        uint256 recoveredAccountIndex = PackedAccountData.accountIndex(packedAccountData);
        if (accountIndex != recoveredAccountIndex) {
            revert MismatchedAccountIndex(accountIndex, recoveredAccountIndex);
        }
        uint256 expectedNonce = accountIndexToSignatureNonce[accountIndex]++;
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(accountIndex, expectedNonce, nonce);
        }

        // Add new authenticator
        authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(accountIndex, uint32(accountIndexToRecoveryCounter[accountIndex]), pubkeyId);
        _setPubkeyBitmap(accountIndex, bitmap | (1 << uint256(pubkeyId)));

        // Update tree
        emit AuthenticatorInserted(
            accountIndex,
            pubkeyId,
            newAuthenticatorAddress,
            newAuthenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(accountIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
    }

    /**
     * @dev Removes an authenticator.
     * @param authenticatorAddress The authenticator address to remove.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function removeAuthenticator(
        uint256 accountIndex,
        address authenticatorAddress,
        uint32 pubkeyId,
        uint256 authenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (pubkeyId >= MAX_AUTHENTICATORS) {
            revert PubkeyIdOutOfBounds();
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    REMOVE_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    authenticatorAddress,
                    pubkeyId,
                    authenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (address signer, uint256 packedAccountData) = recoverAccountDataFromSignature(messageHash, signature);
        uint256 recoveredAccountIndex = PackedAccountData.accountIndex(packedAccountData);
        if (accountIndex != recoveredAccountIndex) {
            revert MismatchedAccountIndex(accountIndex, recoveredAccountIndex);
        }
        uint256 expectedNonce = accountIndexToSignatureNonce[accountIndex]++;
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(accountIndex, expectedNonce, nonce);
        }

        uint256 packedToRemove = authenticatorAddressToPackedAccountData[authenticatorAddress];
        if (packedToRemove == 0) {
            revert AuthenticatorDoesNotExist(authenticatorAddress);
        }
        uint256 actualAccountIndex = PackedAccountData.accountIndex(packedToRemove);
        if (actualAccountIndex != accountIndex) {
            revert AuthenticatorDoesNotBelongToAccount(accountIndex, actualAccountIndex);
        }
        uint256 actualPubkeyId = PackedAccountData.pubkeyId(packedToRemove);
        if (actualPubkeyId != pubkeyId) {
            revert MismatchedPubkeyId(pubkeyId, actualPubkeyId);
        }

        // Delete authenticator
        delete authenticatorAddressToPackedAccountData[authenticatorAddress];
        _setPubkeyBitmap(accountIndex, _getPubkeyBitmap(accountIndex) & ~(1 << pubkeyId));

        // Update tree
        emit AuthenticatorRemoved(
            accountIndex,
            pubkeyId,
            authenticatorAddress,
            authenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(accountIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
    }

    /**
     * @dev Recovers an account.
     * @param accountIndex The index of the account.
     * @param newAuthenticatorAddress The new authenticator address.
     * @param newAuthenticatorPubkey The new authenticator pubkey.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     * @param nonce The signature nonce.
     */
    function recoverAccount(
        uint256 accountIndex,
        address newAuthenticatorAddress,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (accountIndex == 0 || nextAccountIndex <= accountIndex) {
            revert AccountDoesNotExist(accountIndex);
        }
        uint256 expectedNonce = accountIndexToSignatureNonce[accountIndex]++;
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(accountIndex, expectedNonce, nonce);
        }
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECOVER_ACCOUNT_TYPEHASH,
                    accountIndex,
                    newAuthenticatorAddress,
                    newAuthenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        address recoverySigner = _getRecoveryAddress(accountIndex);
        if (recoverySigner == address(0)) {
            revert RecoveryNotEnabled();
        }
        if (!SignatureChecker.isValidSignatureNow(recoverySigner, messageHash, signature)) {
            revert InvalidSignature();
        }
        if (authenticatorAddressToPackedAccountData[newAuthenticatorAddress] != 0) {
            revert AuthenticatorAlreadyExists(newAuthenticatorAddress);
        }
        if (newAuthenticatorAddress == address(0)) {
            revert ZeroAddress();
        }

        accountIndexToRecoveryCounter[accountIndex]++;

        authenticatorAddressToPackedAccountData[newAuthenticatorAddress] =
            PackedAccountData.pack(accountIndex, uint32(accountIndexToRecoveryCounter[accountIndex]), uint32(0));
        _setPubkeyBitmap(accountIndex, 1); // Reset to only pubkeyId 0

        emit AccountRecovered(
            accountIndex,
            newAuthenticatorAddress,
            newAuthenticatorPubkey,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _updateLeafAndRecord(accountIndex, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
    }

    /**
     * @dev Updates the recovery address for an account.
     * @param accountIndex The index of the account.
     * @param newRecoveryAddress The new recovery address.
     * @param signature The signature authorizing the change.
     * @param nonce The signature nonce.
     */
    function updateRecoveryAddress(
        uint256 accountIndex,
        address newRecoveryAddress,
        bytes memory signature,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (accountIndex == 0 || nextAccountIndex <= accountIndex) {
            revert AccountDoesNotExist(accountIndex);
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(UPDATE_RECOVERY_ADDRESS_TYPEHASH, accountIndex, newRecoveryAddress, nonce))
        );

        (, uint256 packedAccountData) = recoverAccountDataFromSignature(messageHash, signature);
        uint256 recoveredAccountIndex = PackedAccountData.accountIndex(packedAccountData);
        if (accountIndex != recoveredAccountIndex) {
            revert MismatchedAccountIndex(accountIndex, recoveredAccountIndex);
        }
        uint256 expectedNonce = accountIndexToSignatureNonce[accountIndex]++;
        if (nonce != expectedNonce) {
            revert MismatchedSignatureNonce(accountIndex, expectedNonce, nonce);
        }

        address oldRecoveryAddress = _getRecoveryAddress(accountIndex);

        // Preserve the bitmap when updating the recovery address
        uint256 bitmap = _getPubkeyBitmap(accountIndex);
        _setRecoveryAddressAndBitmap(accountIndex, newRecoveryAddress, bitmap);

        emit RecoveryAddressUpdated(accountIndex, oldRecoveryAddress, newRecoveryAddress);
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
