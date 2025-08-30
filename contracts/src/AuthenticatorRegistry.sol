// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {LeanIMT, LeanIMTData} from "./tree/LeanIMT.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {console} from "forge-std/console.sol";

contract AuthenticatorRegistry is EIP712, Ownable2Step {
    using LeanIMT for LeanIMTData;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    mapping(uint256 => address) public accountIndexToRecoveryAddress;
    mapping(address => uint256) public authenticatorAddressToPackedAccountIndex;
    mapping(uint256 => uint256) public signatureNonces;
    mapping(uint256 => uint256) public accountRecoveryCounter;

    LeanIMTData public tree;
    uint256 public nextAccountIndex = 1;
    address public defaultRecoveryAddress;

    // Root history tracking
    mapping(uint256 => uint256) public rootToTimestamp;
    uint256 public rootValidityWindow; // seconds; 0 means never expires

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event AccountCreated(
        uint256 indexed accountIndex,
        address indexed recoveryAddress,
        address[] authenticatorAddresses,
        uint256 offchainSignerCommitment
    );
    event AccountUpdated(
        uint256 indexed accountIndex,
        address indexed oldAuthenticatorAddress,
        address indexed newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AccountRecovered(
        uint256 indexed accountIndex,
        address indexed newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AuthenticatorInserted(
        uint256 indexed accountIndex,
        address indexed authenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AuthenticatorRemoved(
        uint256 indexed accountIndex,
        address indexed authenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event RootRecorded(uint256 indexed root, uint256 timestamp);
    event RootValidityWindowUpdated(uint256 oldWindow, uint256 newWindow);

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant UPDATE_AUTHENTICATOR_TYPEDEF =
        "UpdateAuthenticator(uint256 accountIndex, address oldAuthenticatorAddress, address newAuthenticatorAddress, uint256 newOffchainSignerCommitment, uint256 nonce)";
    string public constant INSERT_AUTHENTICATOR_TYPEDEF =
        "InsertAuthenticator(uint256 accountIndex, address newAuthenticatorAddress, uint256 newOffchainSignerCommitment, uint256 nonce)";
    string public constant REMOVE_AUTHENTICATOR_TYPEDEF =
        "RemoveAuthenticator(uint256 accountIndex, address authenticatorAddress, uint256 newOffchainSignerCommitment, uint256 nonce)";
    string public constant RECOVER_ACCOUNT_TYPEDEF =
        "RecoverAccount(uint256 accountIndex, address newAuthenticatorAddress, uint256 newOffchainSignerCommitment, uint256 nonce)";

    bytes32 public constant UPDATE_AUTHENTICATOR_TYPEHASH = keccak256(abi.encodePacked(UPDATE_AUTHENTICATOR_TYPEDEF));
    bytes32 public constant INSERT_AUTHENTICATOR_TYPEHASH = keccak256(abi.encodePacked(INSERT_AUTHENTICATOR_TYPEDEF));
    bytes32 public constant REMOVE_AUTHENTICATOR_TYPEHASH = keccak256(abi.encodePacked(REMOVE_AUTHENTICATOR_TYPEDEF));
    bytes32 public constant RECOVER_ACCOUNT_TYPEHASH = keccak256(abi.encodePacked(RECOVER_ACCOUNT_TYPEDEF));

    string public constant EIP712_NAME = "AuthenticatorRegistry";
    string public constant EIP712_VERSION = "1.0";

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    constructor(address _defaultRecoveryAddress) EIP712(EIP712_NAME, EIP712_VERSION) Ownable(msg.sender) {
        defaultRecoveryAddress = _defaultRecoveryAddress;
    }

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Initializes the tree.
     * @param depth The depth of the tree.
     * @param size The size of the tree.
     * @param sideNodes The side nodes of the tree.
     */
    function initTree(uint256 depth, uint256 size, uint256[] calldata sideNodes) external {
        nextAccountIndex = size + 1;
        LeanIMT.initialize(tree, depth, size, sideNodes);
        _recordCurrentRoot();
    }

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
        return LeanIMT.root(tree);
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
        uint256 root = LeanIMT.root(tree);
        rootToTimestamp[root] = block.timestamp;
        emit RootRecorded(root, block.timestamp);
    }

    /**
     * @dev Recovers the account index from a message hash and a signature.
     * @param messageHash The message hash.
     * @param signature The signature.
     * @return The account index.
     */
    function recoverAccountIndex(bytes32 messageHash, bytes memory signature) internal view returns (uint256) {
        address signatureRecoveredAddress = ECDSA.recover(messageHash, signature);
        require(signatureRecoveredAddress != address(0), "Invalid signature");
        uint256 accountIndexPacked = authenticatorAddressToPackedAccountIndex[signatureRecoveredAddress];
        require(accountIndexPacked != 0, "Account does not exist");
        uint256 accountIndex = uint256(uint128(accountIndexPacked));
        require(accountIndexPacked >> 128 == accountRecoveryCounter[accountIndex], "Invalid account recovery counter");
        return accountIndex;
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
        uint256 offchainSignerCommitment
    ) external {
        require(authenticatorAddresses.length > 0, "authenticatorAddresses length must be greater than 0");

        if (recoveryAddress != address(0)) {
            accountIndexToRecoveryAddress[nextAccountIndex] = recoveryAddress;
        }

        for (uint256 i = 0; i < authenticatorAddresses.length; i++) {
            require(authenticatorAddresses[i] != address(0), "Authenticator cannot be the zero address");
            require(
                authenticatorAddressToPackedAccountIndex[authenticatorAddresses[i]] == 0, "Authenticator already exists"
            );
            authenticatorAddressToPackedAccountIndex[authenticatorAddresses[i]] = nextAccountIndex;
        }

        // Update tree
        tree.insert(offchainSignerCommitment);
        _recordCurrentRoot();

        emit AccountCreated(nextAccountIndex, recoveryAddress, authenticatorAddresses, offchainSignerCommitment);

        nextAccountIndex++;
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
        uint256[] calldata offchainSignerCommitments
    ) external {
        require(recoveryAddresses.length > 0, "Length must be greater than 0");
        require(
            recoveryAddresses.length == authenticatorAddresses.length,
            "Recovery addresses and authenticator addresses length mismatch"
        );
        require(
            recoveryAddresses.length == offchainSignerCommitments.length,
            "Recovery addresses and offchain signer commitments length mismatch"
        );

        for (uint256 i = 0; i < recoveryAddresses.length; i++) {
            require(authenticatorAddresses[i].length > 0, "Authenticator addresses length must be greater than 0");
            accountIndexToRecoveryAddress[nextAccountIndex] = recoveryAddresses[i];
            for (uint256 j = 0; j < authenticatorAddresses[i].length; j++) {
                require(authenticatorAddresses[i][j] != address(0), "Authenticator cannot be the zero address");
                require(
                    authenticatorAddressToPackedAccountIndex[authenticatorAddresses[i][j]] == 0,
                    "Authenticator already exists"
                );
                authenticatorAddressToPackedAccountIndex[authenticatorAddresses[i][j]] = nextAccountIndex;
            }

            emit AccountCreated(
                nextAccountIndex, recoveryAddresses[i], authenticatorAddresses[i], offchainSignerCommitments[i]
            );

            nextAccountIndex++;
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
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external {
        require(authenticatorAddressToPackedAccountIndex[oldAuthenticatorAddress] != 0, "Authenticator does not exist");
        require(authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");
        require(
            oldAuthenticatorAddress != newAuthenticatorAddress, "Old and new authenticator addresses cannot be the same"
        );
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    UPDATE_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    oldAuthenticatorAddress,
                    newAuthenticatorAddress,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        require(accountIndex == recoverAccountIndex(messageHash, signature), "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");
        require(
            uint256(uint128(authenticatorAddressToPackedAccountIndex[oldAuthenticatorAddress])) == accountIndex,
            "Authenticator does not belong to account"
        );

        // Delete old authenticator
        delete authenticatorAddressToPackedAccountIndex[oldAuthenticatorAddress];

        // Add new authenticator
        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            (accountRecoveryCounter[accountIndex] << 128) | accountIndex;

        // Update tree
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        emit AccountUpdated(
            accountIndex,
            oldAuthenticatorAddress,
            newAuthenticatorAddress,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
        _recordCurrentRoot();
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
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external {
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");
        require(authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    INSERT_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    newAuthenticatorAddress,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        require(accountIndex == recoverAccountIndex(messageHash, signature), "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");

        // Add new authenticator
        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            (accountRecoveryCounter[accountIndex] << 128) | accountIndex;

        // Update tree
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        emit AuthenticatorInserted(
            accountIndex, newAuthenticatorAddress, oldOffchainSignerCommitment, newOffchainSignerCommitment
        );
        _recordCurrentRoot();
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
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) external {
        require(authenticatorAddressToPackedAccountIndex[authenticatorAddress] != 0, "Authenticator does not exist");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    REMOVE_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    authenticatorAddress,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        require(accountIndex == recoverAccountIndex(messageHash, signature), "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");
        require(
            uint256(uint128(authenticatorAddressToPackedAccountIndex[authenticatorAddress])) == accountIndex,
            "Authenticator does not belong to account"
        );

        // Delete authenticator
        delete authenticatorAddressToPackedAccountIndex[authenticatorAddress];

        // Update tree
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        emit AuthenticatorRemoved(
            accountIndex, authenticatorAddress, oldOffchainSignerCommitment, newOffchainSignerCommitment
        );
        _recordCurrentRoot();
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
                    RECOVER_ACCOUNT_TYPEHASH, accountIndex, newAuthenticatorAddress, newOffchainSignerCommitment, nonce
                )
            )
        );

        address signatureRecoveredAddress = ECDSA.recover(messageHash, signature);
        require(signatureRecoveredAddress != address(0), "Invalid signature");
        require(
            signatureRecoveredAddress == accountIndexToRecoveryAddress[accountIndex]
                || signatureRecoveredAddress == defaultRecoveryAddress,
            "Invalid signature"
        );
        require(authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");

        accountRecoveryCounter[accountIndex]++;

        authenticatorAddressToPackedAccountIndex[newAuthenticatorAddress] =
            (accountRecoveryCounter[accountIndex] << 128) | accountIndex;

        // Update tree
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        emit AccountRecovered(
            accountIndex, newAuthenticatorAddress, oldOffchainSignerCommitment, newOffchainSignerCommitment
        );
        _recordCurrentRoot();
    }
}
