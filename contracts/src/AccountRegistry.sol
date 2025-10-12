// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BinaryIMT, BinaryIMTData} from "./tree/BinaryIMT.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

contract AccountRegistry is EIP712, Ownable2Step {
    using BinaryIMT for BinaryIMTData;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    mapping(uint256 => address) public accountIndexToRecoveryAddress;
    // [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
    mapping(address => uint256) public authenticatorAddressToPackedAccountIndex;
    mapping(uint256 => uint256) public signatureNonces;
    mapping(uint256 => uint256) public accountRecoveryCounter;

    BinaryIMTData public tree;
    uint256 public nextAccountIndex = 1;

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

    constructor(uint256 treeDepth) EIP712(EIP712_NAME, EIP712_VERSION) Ownable(msg.sender) {
        tree.initWithDefaultZeroes(treeDepth);
    }

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Returns the domain separator for the EIP712 structs.
     */
    function domainSeparatorV4() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Returns the current tree root.
     */
    function currentRoot() external view returns (uint256) {
        return tree.root;
    }

    /**
     * @dev Sets the validity window for historic roots. 0 means roots never expire.
     */
    function setRootValidityWindow(uint256 newWindow) external onlyOwner {
        uint256 old = rootValidityWindow;
        rootValidityWindow = newWindow;
        emit RootValidityWindowUpdated(old, newWindow);
    }

    /**
     * @dev Checks whether `root` is known and not expired according to `rootValidityWindow`.
     */
    function isValidRoot(uint256 root) external view returns (bool) {
        uint256 ts = rootToTimestamp[root];
        if (ts == 0) return false;
        if (rootValidityWindow == 0) return true;
        return block.timestamp <= ts + rootValidityWindow;
    }

    /**
     * @dev Records the current tree root.
     */
    function _recordCurrentRoot() internal {
        uint256 root = tree.root;
        rootToTimestamp[root] = block.timestamp;
        emit RootRecorded(root, block.timestamp, rootEpoch++);
    }

    function _updateLeafAndRecord(
        uint256 accountIndex,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        uint256[] calldata siblingNodes
    ) internal {
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
    function recoverAccountIndex(bytes32 messageHash, bytes memory signature)
        internal
        view
        returns (uint256 accountIndex, address signer, uint256 packedAccountIndex)
    {
        signer = ECDSA.recover(messageHash, signature);
        require(signer != address(0), "Invalid signature");
        packedAccountIndex = authenticatorAddressToPackedAccountIndex[signer];
        require(packedAccountIndex != 0, "Account does not exist");
        accountIndex = uint256(uint192(packedAccountIndex));
        require(packedAccountIndex >> 224 == accountRecoveryCounter[accountIndex], "Invalid account recovery counter");
    }

    function _pack(uint256 accountIndex, uint32 recoveryCounter, uint32 pubkeyId) internal pure returns (uint256) {
        require(accountIndex >> 192 == 0, "accountIndex overflow");
        return (uint256(recoveryCounter) << 224) | (uint256(pubkeyId) << 192) | accountIndex;
    }

    function _pubkeyIdOf(uint256 packed) internal pure returns (uint32) {
        return uint32(packed >> 192);
    }

    function _registerAccount(
        address recoveryAddress,
        address[] calldata authenticatorAddresses,
        uint256[] calldata authenticatorPubkeys,
        uint256 offchainSignerCommitment
    ) internal {
        require(authenticatorAddresses.length > 0, "authenticatorAddresses length must be greater than 0");
        require(
            authenticatorAddresses.length == authenticatorPubkeys.length,
            "authenticatorAddresses and authenticatorPubkeys length mismatch"
        );
        require(recoveryAddress != address(0), "Recovery address cannot be the zero address");

        uint256 accountIndex = nextAccountIndex;
        accountIndexToRecoveryAddress[accountIndex] = recoveryAddress;

        for (uint256 i = 0; i < authenticatorAddresses.length; i++) {
            address authenticator = authenticatorAddresses[i];
            require(authenticator != address(0), "Authenticator cannot be the zero address");
            require(authenticatorAddressToPackedAccountIndex[authenticator] == 0, "Authenticator already exists");
            authenticatorAddressToPackedAccountIndex[authenticator] = _pack(accountIndex, 0, uint32(i));
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
    ) external {
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
    ) external {
        require(recoveryAddresses.length > 0, "Length must be greater than 0");
        require(
            recoveryAddresses.length == authenticatorAddresses.length,
            "Recovery addresses and authenticator addresses length mismatch"
        );
        require(
            recoveryAddresses.length == authenticatorPubkeys.length,
            "Recovery addresses and authenticator pubkeys length mismatch"
        );
        require(
            recoveryAddresses.length == offchainSignerCommitments.length,
            "Recovery addresses and offchain signer commitments length mismatch"
        );

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
    ) external {
        require(authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");
        require(
            oldAuthenticatorAddress != newAuthenticatorAddress, "Old and new authenticator addresses cannot be the same"
        );
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");

        require(uint256(uint32(pubkeyId)) == pubkeyId, "pubkeyId overflow");

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
            recoverAccountIndex(messageHash, signature);
        require(accountIndex == recoveredAccountIndex, "Invalid account index");
        require(signer == oldAuthenticatorAddress, "Invalid authenticator");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");
        require(_pubkeyIdOf(packedAccountIndex) == uint32(pubkeyId), "Invalid pubkeyId");

        // Delete old authenticator
        delete authenticatorAddressToPackedAccountIndex[
            oldAuthenticatorAddress
        ];

        // Add new authenticator
        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            _pack(accountIndex, uint32(accountRecoveryCounter[accountIndex]), uint32(pubkeyId));

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
    ) external {
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");
        require(authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");

        require(uint256(uint32(pubkeyId)) == pubkeyId, "pubkeyId overflow");

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

        (uint256 recoveredAccountIndex,,) = recoverAccountIndex(messageHash, signature);
        require(accountIndex == recoveredAccountIndex, "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");

        // Add new authenticator
        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            _pack(accountIndex, uint32(accountRecoveryCounter[accountIndex]), uint32(pubkeyId));

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
    ) external {
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

        (uint256 recoveredAccountIndex,,) = recoverAccountIndex(messageHash, signature);
        require(accountIndex == recoveredAccountIndex, "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");

        uint256 packedToRemove = authenticatorAddressToPackedAccountIndex[authenticatorAddress];
        require(packedToRemove != 0, "Authenticator does not exist");
        require(uint192(packedToRemove) == accountIndex, "Authenticator does not belong to account");
        require(_pubkeyIdOf(packedToRemove) == uint32(pubkeyId), "Invalid pubkeyId");

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
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
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
    ) external {
        require(accountIndex > 0, "Account index must be greater than 0");
        require(nextAccountIndex > accountIndex, "Account does not exist");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");

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
        require(signatureRecoveredAddress != address(0), "Invalid signature");
        address recoverySigner = accountIndexToRecoveryAddress[accountIndex];
        require(recoverySigner != address(0), "Recovery address not set");
        require(signatureRecoveredAddress == recoverySigner, "Invalid signature");
        require(authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");

        accountRecoveryCounter[accountIndex]++;

        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            _pack(accountIndex, uint32(accountRecoveryCounter[accountIndex]), uint32(0));

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
    ) external {
        require(accountIndex > 0, "Account index must be greater than 0");
        require(nextAccountIndex > accountIndex, "Account does not exist");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(UPDATE_RECOVERY_ADDRESS_TYPEHASH, accountIndex, newRecoveryAddress, nonce))
        );

        (uint256 recoveredAccountIndex,,) = recoverAccountIndex(messageHash, signature);
        require(accountIndex == recoveredAccountIndex, "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");

        require(newRecoveryAddress != address(0), "Recovery address cannot be the zero address");

        address oldRecoveryAddress = accountIndexToRecoveryAddress[accountIndex];
        require(oldRecoveryAddress != address(0), "Recovery address not set");

        accountIndexToRecoveryAddress[accountIndex] = newRecoveryAddress;

        emit RecoveryAddressUpdated(accountIndex, oldRecoveryAddress, newRecoveryAddress);
    }
}
