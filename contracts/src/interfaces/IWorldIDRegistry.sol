// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title IWorldIDRegistry
 * @author World Contributors
 * @dev Interface for the World ID Registry contract
 */
interface IWorldIDRegistry {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    error ImplementationNotInitialized();

    /**
     * @dev Thrown when a requested on-chain signer address is already in use by another account as an authenticator.
     */
    error AuthenticatorAddressAlreadyInUse(address authenticatorAddress);

    /**
     * @dev Thrown when the pubkey bitmap overflows.
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
     * @dev Thrown when a pubkey ID does not exist.
     */
    error PubkeyIdDoesNotExist();

    /**
     * @dev Thrown when there is no Recovery Agent (i.e. recovery address) set for the account.
     */
    error RecoveryNotEnabled();

    /**
     * @dev Thrown when a requested leaf index does not exist.
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
     */
    error AuthenticatorAlreadyExists(address authenticatorAddress);

    /**
     * @dev Thrown when the leaf index does not match the expected value.
     */
    error MismatchedLeafIndex(uint256 expectedLeafIndex, uint256 actualLeafIndex);

    /**
     * @dev Thrown when the recovered signature does not match the expected authenticator address.
     */
    error MismatchedAuthenticatorSigner(address expectedAuthenticatorAddress, address actualAuthenticatorAddress);

    /**
     * @dev Thrown when a pubkey ID does not match the expected value.
     */
    error MismatchedPubkeyId(uint256 expectedPubkeyId, uint256 actualPubkeyId);

    /**
     * @dev Thrown when a nonce does not match the expected value.
     */
    error MismatchedSignatureNonce(uint256 leafIndex, uint256 expectedNonce, uint256 actualNonce);

    /**
     * @dev Thrown when a recovery counter does not match the expected value.
     */
    error MismatchedRecoveryCounter(uint256 leafIndex, uint256 expectedRecoveryCounter, uint256 actualRecoveryCounter);

    /**
     * @dev Thrown when a pubkey ID overflows its uint32 limit.
     */
    error PubkeyIdOverflow(uint256 pubkeyId);

    /**
     * @dev Thrown when a recovery address is not set for an account.
     */
    error RecoveryAddressNotSet(uint256 leafIndex);

    /**
     * @dev Thrown when an authenticator does not exist.
     */
    error AuthenticatorDoesNotExist(address authenticatorAddress);

    /**
     * @dev Thrown when an authenticator does not belong to the specified account.
     */
    error AuthenticatorDoesNotBelongToAccount(uint256 expectedLeafIndex, uint256 actualLeafIndex);

    /**
     * @dev Thrown when trying to update max authenticators beyond the natural limit.
     */
    error OwnerMaxAuthenticatorsOutOfBounds();

    /**
     * @dev Thrown when the recovery counter would overflow its uint32 limit.
     */
    error RecoveryCounterOverflow();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
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
    //                   PUBLIC FUNCTIONS                     //
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
    ) external;

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
    ) external;

    /**
     * @dev Updates an existing authenticator for a World ID account. Replaces the old authenticator address with a new one.
     * @param leafIndex The leaf index of the World ID account.
     * @param oldAuthenticatorAddress The current authenticator address to be replaced.
     * @param newAuthenticatorAddress The new authenticator address to replace the old one.
     * @param pubkeyId The pubkey ID associated with this authenticator.
     * @param newAuthenticatorPubkey The new authenticator public key.
     * @param oldOffchainSignerCommitment The current offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature from the old authenticator authorizing the update.
     * @param siblingNodes The Merkle proof sibling nodes for the current leaf.
     * @param nonce The signature nonce for replay protection.
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
    ) external;

    /**
     * @dev Inserts a new authenticator for a World ID account. Adds an additional authenticator to an existing account.
     * @param leafIndex The leaf index of the World ID account.
     * @param newAuthenticatorAddress The new authenticator address to add.
     * @param pubkeyId The pubkey ID to assign to this new authenticator (must be unused).
     * @param newAuthenticatorPubkey The new authenticator public key.
     * @param oldOffchainSignerCommitment The current offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature from an existing authenticator authorizing the insertion.
     * @param siblingNodes The Merkle proof sibling nodes for the current leaf.
     * @param nonce The signature nonce for replay protection.
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
    ) external;

    /**
     * @dev Removes an authenticator from a World ID account.
     * @param leafIndex The leaf index of the World ID account.
     * @param authenticatorAddress The authenticator address to remove.
     * @param pubkeyId The pubkey ID associated with the authenticator being removed.
     * @param authenticatorPubkey The public key of the authenticator being removed.
     * @param oldOffchainSignerCommitment The current offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment after removal.
     * @param signature The signature from the authenticator being removed authorizing the removal.
     * @param siblingNodes The Merkle proof sibling nodes for the current leaf.
     * @param nonce The signature nonce for replay protection.
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
    ) external;

    /**
     * @dev Recovers a World ID account using the recovery address. Replaces all authenticators with a new one.
     * @param leafIndex The leaf index of the World ID account to recover.
     * @param newAuthenticatorAddress The new authenticator address to set after recovery.
     * @param newAuthenticatorPubkey The new authenticator public key.
     * @param oldOffchainSignerCommitment The current offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment after recovery.
     * @param signature The signature from the recovery address authorizing the recovery.
     * @param siblingNodes The Merkle proof sibling nodes for the current leaf.
     * @param nonce The signature nonce for replay protection.
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
    ) external;

    /**
     * @dev Updates the recovery address for a World ID account.
     * @param leafIndex The leaf index of the World ID account.
     * @param newRecoveryAddress The new recovery address to set.
     * @param signature The signature from an existing authenticator authorizing the update.
     * @param nonce The signature nonce for replay protection.
     */
    function updateRecoveryAddress(uint256 leafIndex, address newRecoveryAddress, bytes memory signature, uint256 nonce)
        external;

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Returns the domain separator for the EIP712 structs.
     */
    function domainSeparatorV4() external view returns (bytes32);

    /**
     * @dev Returns the current tree root.
     */
    function currentRoot() external view returns (uint256);

    /**
     * @dev Returns the recovery address for the given World ID (based on its leaf index).
     * @param leafIndex The index of the leaf.
     */
    function getRecoveryAddress(uint256 leafIndex) external view returns (address);

    /**
     * @dev Checks whether `root` is known and not expired according to `rootValidityWindow`.
     */
    function isValidRoot(uint256 root) external view returns (bool);

    /**
     * @dev Returns the packed account data for an authenticator address.
     * @param authenticatorAddress The authenticator address to query.
     */
    function getPackedAccountData(address authenticatorAddress) external view returns (uint256);

    /**
     * @dev Returns the signature nonce for a leaf index.
     * @param leafIndex The leaf index to query.
     */
    function getSignatureNonce(uint256 leafIndex) external view returns (uint256);

    /**
     * @dev Returns the recovery counter for a leaf index.
     * @param leafIndex The leaf index to query.
     */
    function getRecoveryCounter(uint256 leafIndex) external view returns (uint256);

    /**
     * @dev Returns the next available leaf index.
     */
    function getNextLeafIndex() external view returns (uint256);

    /**
     * @dev Returns the depth of the Merkle tree.
     */
    function getTreeDepth() external view returns (uint256);

    /**
     * @dev Returns the maximum number of authenticators allowed per account.
     */
    function getMaxAuthenticators() external view returns (uint256);

    /**
     * @dev Returns the timestamp when a root was recorded.
     * @param root The root to query.
     */
    function getRootTimestamp(uint256 root) external view returns (uint256);

    /**
     * @dev Returns the latest root.
     */
    function getLatestRoot() external view returns (uint256);

    /**
     * @dev Returns the root validity window in seconds.
     */
    function getRootValidityWindow() external view returns (uint256);

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Sets the validity window for historic roots.
     */
    function setRootValidityWindow(uint256 newWindow) external;

    /**
     * @dev Set an updated maximum number of authenticators allowed.
     */
    function setMaxAuthenticators(uint256 newMaxAuthenticators) external;
}

