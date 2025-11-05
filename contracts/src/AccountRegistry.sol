// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BinaryIMT, BinaryIMTData} from "./tree/BinaryIMT.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {PackedAccountIndex} from "./lib/PackedAccountIndex.sol";

contract AccountRegistry is Initializable, EIP712Upgradeable, Ownable2StepUpgradeable, UUPSUpgradeable {
    using BinaryIMT for BinaryIMTData;

    error ImplementationNotInitialized();

    /**
     * @dev Thrown when a requested on-chain signer address is already in use by another account as an authenticator. An on-chain signer address
     * can only be used by one account at a time.
     * @param authenticatorAddress The target address that is already in use.
     */
    error AuthenticatorAddressAlreadyInUse(address authenticatorAddress);

    /**
     * @dev Thrown when a signature is invalid.
     */
    error InvalidSignature();

    /**
     * @dev Thrown when a requested account recovery counter is invalid.
     * @param accountIndex The account index that does not exist.
     * @param expectedRecoveryCounter The expected recovery counter for the account index.
     * @param actualRecoveryCounter The actual recovery counter for the account index.
     */
    error InvalidAccountRecoveryCounter(
        uint256 accountIndex, uint256 expectedRecoveryCounter, uint256 actualRecoveryCounter
    );

    /**
     * @dev Thrown when a requested account index does not exist.
     * @param accountIndex The account index that does not exist.
     */
    error AccountIndexDoesNotExist(uint256 accountIndex);

    /**
     * @dev Thrown when setting a recovery or authenticator address to the zero address.
     */
    error ZeroAddress();

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
     * @dev Thrown when the account index does not match the expected value.
     * @param expectedAccountIndex The expected account index.
     * @param actualAccountIndex The actual account index.
     */
    error InvalidAccountIndex(uint256 expectedAccountIndex, uint256 actualAccountIndex);

    /**
     * @dev Thrown when the recovered signature does match the expected authenticator address.
     * @param expectedAuthenticatorAddress The expected authenticator address.
     * @param actualAuthenticatorAddress The actual authenticator address.
     */
    error InvalidAuthenticatorSignature(address expectedAuthenticatorAddress, address actualAuthenticatorAddress);

    /**
     * @dev Thrown when the old and new authenticator addresses are the same.
     */
    error OldAndNewAuthenticatorAddressesCannotBeTheSame();

    /**
     * @dev Thrown when a pubkey ID overflows its uint32 limit.
     * @param pubkeyId The pubkey ID that caused the overflow.
     */
    error PubkeyIdOverflow(uint256 pubkeyId);

    /**
     * @dev Thrown when a nonce does not match the expected value.
     * @param expectedNonce The expected nonce value.
     * @param actualNonce The actual nonce value.
     */
    error InvalidNonce(uint256 expectedNonce, uint256 actualNonce);

    /**
     * @dev Thrown when an account index is zero or invalid.
     * @param accountIndex The invalid account index.
     */
    error InvalidAccountIndexValue(uint256 accountIndex);

    /**
     * @dev Thrown when an account does not exist (nextAccountIndex <= accountIndex).
     * @param accountIndex The account index that does not exist.
     * @param nextAccountIndex The next available account index.
     */
    error AccountDoesNotExist(uint256 accountIndex, uint256 nextAccountIndex);

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

    /**
     * @dev Thrown when a pubkey ID does not match the expected value.
     * @param expectedPubkeyId The expected pubkey ID.
     * @param actualPubkeyId The actual pubkey ID.
     */
    error InvalidPubkeyId(uint256 expectedPubkeyId, uint256 actualPubkeyId);

    modifier onlyInitialized() {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
        _;
    }

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // accountIndex -> recoveryAddress, used for recovery of accounts
    mapping(uint256 => address) public accountIndexToRecoveryAddress;

    // authenticatorAddress -> [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
    mapping(address => uint256) public authenticatorAddressToPackedAccountIndex;

    // accountIndex -> nonce, used for prevent replay attacks on updates to authenticators
    mapping(uint256 => uint256) public signatureNonces;

    // accountIndex -> recoveryCounter, used for prevent replay attacks on recovery of accounts
    mapping(uint256 => uint256) public accountRecoveryCounter;

    BinaryIMTData public tree;
    uint256 public nextAccountIndex;

    // Root history tracking
    mapping(uint256 => uint256) public rootToTimestamp;
    uint256 public rootValidityWindow;
    uint256 public rootEpoch;

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
        uint256 pubkeyId,
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
        uint256 pubkeyId,
        address indexed authenticatorAddress,
        uint256 indexed newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AuthenticatorRemoved(
        uint256 indexed accountIndex,
        uint256 pubkeyId,
        address indexed authenticatorAddress,
        uint256 indexed authenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event RootRecorded(uint256 indexed root, uint256 timestamp, uint256 indexed rootEpoch);
    event RootValidityWindowUpdated(uint256 oldWindow, uint256 newWindow);

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    bytes32 public constant UPDATE_AUTHENTICATOR_TYPEHASH = keccak256(
        "UpdateAuthenticator(uint256 accountIndex,address oldAuthenticatorAddress,address newAuthenticatorAddress,uint256 pubkeyId,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant INSERT_AUTHENTICATOR_TYPEHASH = keccak256(
        "InsertAuthenticator(uint256 accountIndex,address newAuthenticatorAddress,uint256 pubkeyId,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant REMOVE_AUTHENTICATOR_TYPEHASH = keccak256(
        "RemoveAuthenticator(uint256 accountIndex,address authenticatorAddress,uint256 pubkeyId,uint256 authenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant RECOVER_ACCOUNT_TYPEHASH = keccak256(
        "RecoverAccount(uint256 accountIndex,address newAuthenticatorAddress,uint256 newAuthenticatorPubkey,uint256 newOffchainSignerCommitment,uint256 nonce)"
    );
    bytes32 public constant UPDATE_RECOVERY_ADDRESS_TYPEHASH =
        keccak256("UpdateRecoveryAddress(uint256 accountIndex,address newRecoveryAddress,uint256 nonce)");

    string public constant EIP712_NAME = "AccountRegistry";
    string public constant EIP712_VERSION = "1.0";

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract.
     * @param treeDepth The depth of the Merkle tree.
     */
    function initialize(uint256 treeDepth) public virtual initializer {
        __EIP712_init(EIP712_NAME, EIP712_VERSION);
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        tree.initWithDefaultZeroes(treeDepth);
        nextAccountIndex = 1;
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
        uint256 ts = rootToTimestamp[root];
        if (ts == 0) return false;
        if (rootValidityWindow == 0) return true;
        return block.timestamp <= ts + rootValidityWindow;
    }

    /**
     * @dev Records the current tree root.
     */
    function _recordCurrentRoot() internal virtual {
        uint256 root = tree.root;
        rootToTimestamp[root] = block.timestamp;
        emit RootRecorded(root, block.timestamp, rootEpoch++);
    }

    function _updateLeafAndRecord(
        uint256 accountIndex,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        uint256[] calldata siblingNodes
    ) internal virtual {
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        _recordCurrentRoot();
    }

    /**
     * @dev Recovers the packed authenticator metadata for the signer of `messageHash`.
     * @param messageHash The message hash.
     * @param signature The signature.
     * @return accountIndex Index of the account the signer belongs to.
     * @return signer Address recovered from the signature.
     * @return packedAccountIndex Packed authenticator data for the signer.
     */
    function recoverAccountIndexFromSignature(bytes32 messageHash, bytes memory signature)
        internal
        view
        virtual
        returns (uint256 accountIndex, address signer, uint256 packedAccountIndex)
    {
        signer = ECDSA.recover(messageHash, signature);
        if (signer == address(0)) {
            revert InvalidSignature();
        }
        packedAccountIndex = authenticatorAddressToPackedAccountIndex[signer];
        if (packedAccountIndex == 0) {
            revert AccountIndexDoesNotExist(accountIndex);
        }
        accountIndex = PackedAccountIndex.accountIndex(packedAccountIndex);
        uint256 actualRecoveryCounter = PackedAccountIndex.recoveryCounter(packedAccountIndex);
        uint256 expectedRecoveryCounter = accountRecoveryCounter[accountIndex];
        if (actualRecoveryCounter != expectedRecoveryCounter) {
            revert InvalidAccountRecoveryCounter(accountIndex, expectedRecoveryCounter, actualRecoveryCounter);
        }
    }

    function _registerAccount(
        address recoveryAddress,
        address[] calldata authenticatorAddresses,
        uint256[] calldata authenticatorPubkeys,
        uint256 offchainSignerCommitment
    ) internal virtual {
        if (authenticatorAddresses.length == 0) {
            revert EmptyAddressArray();
        }
        if (authenticatorAddresses.length != authenticatorPubkeys.length) {
            revert MismatchingArrayLengths(authenticatorAddresses.length, authenticatorPubkeys.length);
        }
        if (recoveryAddress == address(0)) {
            revert ZeroAddress();
        }

        uint256 accountIndex = nextAccountIndex;
        accountIndexToRecoveryAddress[accountIndex] = recoveryAddress;

        for (uint256 i = 0; i < authenticatorAddresses.length; i++) {
            address authenticatorAddress = authenticatorAddresses[i];
            if (authenticatorAddress == address(0)) {
                revert ZeroAddress();
            }

            uint256 packedAccountIndex = authenticatorAddressToPackedAccountIndex[authenticatorAddress];
            // If the authenticatorAddress is non-zero, we could permit it to be used if the recovery counter is less than the
            // accountIndex's recovery counter. This means the account was recovered and the authenticator address is no longer in use.
            if (packedAccountIndex != 0) {
                uint256 existingAccountIndex = PackedAccountIndex.accountIndex(packedAccountIndex);
                uint256 existingRecoveryCounter = PackedAccountIndex.recoveryCounter(packedAccountIndex);
                if (existingRecoveryCounter >= accountRecoveryCounter[existingAccountIndex]) {
                    revert AuthenticatorAddressAlreadyInUse(authenticatorAddress);
                }
            }
            authenticatorAddressToPackedAccountIndex[authenticatorAddress] =
                PackedAccountIndex.pack(accountIndex, 0, uint32(i));
        }

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
        uint256 pubkeyId,
        uint256 newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external virtual onlyProxy onlyInitialized {
        if (authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] != 0) {
            revert AuthenticatorAddressAlreadyInUse(newAuthenticatorAddress);
        }
        if (oldAuthenticatorAddress != newAuthenticatorAddress) {
            revert OldAndNewAuthenticatorAddressesCannotBeTheSame();
        }

        if (newAuthenticatorAddress == address(0)) {
            revert ZeroAddress();
        }
        if (uint256(uint32(pubkeyId)) != pubkeyId) {
            revert PubkeyIdOverflow();
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

        (uint256 recoveredAccountIndex, address signer, uint256 packedAccountIndex) =
            recoverAccountIndexFromSignature(messageHash, signature);
        if (accountIndex != recoveredAccountIndex) {
            revert InvalidAccountIndex(recoveredAccountIndex, accountIndex);
        }
        if (signer != oldAuthenticatorAddress) {
            revert InvalidAuthenticatorSignature(oldAuthenticatorAddress, signer);
        }
        // Should nonce always be incremented even if the method reverts?
        if (nonce != signatureNonces[accountIndex]++) {
            revert InvalidNonce(signatureNonces[accountIndex], nonce);
        }
        if (PackedAccountIndex.pubkeyId(packedAccountIndex) != pubkeyId) {
            revert InvalidPubkeyId(packedAccountIndex, pubkeyId);
        }

        // Delete old authenticator
        delete authenticatorAddressToPackedAccountIndex[oldAuthenticatorAddress];

        // Add new authenticator
        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            PackedAccountIndex.pack(accountIndex, uint32(accountRecoveryCounter[accountIndex]), uint32(pubkeyId));

        // Update tree
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
        uint256 pubkeyId,
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
        if (authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] != 0) {
            revert AuthenticatorAddressAlreadyInUse(newAuthenticatorAddress);
        }

        if (uint256(uint32(pubkeyId)) != pubkeyId) {
            revert PubkeyIdOverflow(pubkeyId);
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

        (uint256 recoveredAccountIndex,,) = recoverAccountIndexFromSignature(messageHash, signature);
        if (accountIndex != recoveredAccountIndex) {
            revert InvalidAccountIndex(accountIndex, recoveredAccountIndex);
        }
        uint256 expectedNonce = signatureNonces[accountIndex]++;
        if (nonce != expectedNonce) {
            revert InvalidNonce(expectedNonce, nonce);
        }

        // Add new authenticator
        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            PackedAccountIndex.pack(accountIndex, uint32(accountRecoveryCounter[accountIndex]), uint32(pubkeyId));

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
        uint256 pubkeyId,
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
                    accountIndex,
                    authenticatorAddress,
                    pubkeyId,
                    authenticatorPubkey,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        (uint256 recoveredAccountIndex,,) = recoverAccountIndexFromSignature(messageHash, signature);
        if (accountIndex != recoveredAccountIndex) {
            revert InvalidAccountIndex(accountIndex, recoveredAccountIndex);
        }
        uint256 expectedNonce = signatureNonces[accountIndex]++;
        if (nonce != expectedNonce) {
            revert InvalidNonce(expectedNonce, nonce);
        }

        uint256 packedToRemove = authenticatorAddressToPackedAccountIndex[authenticatorAddress];
        if (packedToRemove == 0) {
            revert AuthenticatorDoesNotExist(authenticatorAddress);
        }
        uint256 actualAccountIndex = PackedAccountIndex.accountIndex(packedToRemove);
        if (actualAccountIndex != accountIndex) {
            revert AuthenticatorDoesNotBelongToAccount(accountIndex, actualAccountIndex);
        }
        uint256 actualPubkeyId = PackedAccountIndex.pubkeyId(packedToRemove);
        if (actualPubkeyId != pubkeyId) {
            revert InvalidPubkeyId(pubkeyId, actualPubkeyId);
        }

        // Delete authenticator
        delete authenticatorAddressToPackedAccountIndex[authenticatorAddress];

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
        if (accountIndex == 0) {
            revert InvalidAccountIndexValue(accountIndex);
        }
        if (nextAccountIndex <= accountIndex) {
            revert AccountIndexDoesNotExist(accountIndex);
        }
        uint256 expectedNonce = signatureNonces[accountIndex]++;
        if (nonce != expectedNonce) {
            revert InvalidNonce(expectedNonce, nonce);
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

        address signatureRecoveredAddress = ECDSA.recover(messageHash, signature);
        if (signatureRecoveredAddress == address(0)) {
            revert InvalidSignature();
        }
        address recoverySigner = accountIndexToRecoveryAddress[accountIndex];
        if (recoverySigner == address(0)) {
            revert RecoveryAddressNotSet(accountIndex);
        }
        if (signatureRecoveredAddress != recoverySigner) {
            revert InvalidAuthenticatorSignature(recoverySigner, signatureRecoveredAddress);
        }
        if (authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] != 0) {
            revert AuthenticatorAddressAlreadyInUse(newAuthenticatorAddress);
        }
        if (newAuthenticatorAddress == address(0)) {
            revert ZeroAddress();
        }

        accountRecoveryCounter[accountIndex]++;

        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            PackedAccountIndex.pack(accountIndex, uint32(accountRecoveryCounter[accountIndex]), uint32(0));

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
        if (accountIndex == 0) {
            revert InvalidAccountIndexValue(accountIndex);
        }
        if (nextAccountIndex <= accountIndex) {
            revert AccountIndexDoesNotExist(accountIndex);
        }

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(UPDATE_RECOVERY_ADDRESS_TYPEHASH, accountIndex, newRecoveryAddress, nonce))
        );

        (uint256 recoveredAccountIndex,,) = recoverAccountIndexFromSignature(messageHash, signature);
        if (accountIndex != recoveredAccountIndex) {
            revert InvalidAccountIndex(accountIndex, recoveredAccountIndex);
        }
        uint256 expectedNonce = signatureNonces[accountIndex]++;
        if (nonce != expectedNonce) {
            revert InvalidNonce(expectedNonce, nonce);
        }

        if (newRecoveryAddress == address(0)) {
            revert ZeroAddress();
        }

        address oldRecoveryAddress = accountIndexToRecoveryAddress[accountIndex];
        if (oldRecoveryAddress == address(0)) {
            revert RecoveryAddressNotSet(accountIndex);
        }

        accountIndexToRecoveryAddress[accountIndex] = newRecoveryAddress;

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
