// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IWorldIDRegistry
 * @author World Contributors
 * @notice Interface for the World ID Registry contract.
 * @dev Manages World IDs and the authenticators which are authorized to perform operations on behalf of them.
 */
interface IWorldIDRegistry {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev @dev Pending recovery agent update for each leaf index
     */
    struct PendingRecoveryAgentUpdate {
        address newRecoveryAgent;
        uint256 executeAfter;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

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

    /**
     * @dev Thrown when the fee payment is not enough to cover registration.
     */
    error InsufficientFunds();

    /**
     * @dev Thrown when there is no pending recovery agent update for the specified account.
     */
    error NoPendingRecoveryAgentUpdate(uint256 leafIndex);

    /**
     * @dev Thrown when trying to execute a recovery agent update before the cooldown period has elapsed.
     */
    error RecoveryAgentUpdateStillInCooldown(uint256 leafIndex, uint256 executeAfter);

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Emitted when a new World ID account is created.
     * @param leafIndex The leaf index assigned to the new account in the Merkle tree.
     * @param recoveryAddress The address authorized to recover the account.
     * @param authenticatorAddresses The addresses of the initial authenticators.
     * @param authenticatorPubkeys The public keys of the initial authenticators.
     * @param offchainSignerCommitment The offchain signer commitment for the account.
     */
    event AccountCreated(
        uint256 indexed leafIndex,
        address indexed recoveryAddress,
        address[] authenticatorAddresses,
        uint256[] authenticatorPubkeys,
        uint256 offchainSignerCommitment
    );

    /**
     * @dev Emitted when an existing authenticator is updated (replaced) on a World ID account.
     * @param leafIndex The leaf index of the account in the Merkle tree.
     * @param pubkeyId The pubkey ID associated with this authenticator.
     * @param newAuthenticatorPubkey The new authenticator public key.
     * @param oldAuthenticatorAddress The previous authenticator address.
     * @param newAuthenticatorAddress The new authenticator address.
     * @param oldOffchainSignerCommitment The previous offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     */
    event AccountUpdated(
        uint256 indexed leafIndex,
        uint32 pubkeyId,
        uint256 newAuthenticatorPubkey,
        address indexed oldAuthenticatorAddress,
        address indexed newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );

    /**
     * @dev Emitted when a World ID account is recovered using the recovery address.
     * @param leafIndex The leaf index of the account in the Merkle tree.
     * @param newAuthenticatorAddress The new authenticator address set after recovery.
     * @param newAuthenticatorPubkey The new authenticator public key.
     * @param oldOffchainSignerCommitment The previous offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     */
    event AccountRecovered(
        uint256 indexed leafIndex,
        address indexed newAuthenticatorAddress,
        uint256 indexed newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );

    /**
     * @dev Emitted when a new authenticator is inserted (added) to a World ID account.
     * @param leafIndex The leaf index of the account in the Merkle tree.
     * @param pubkeyId The pubkey ID assigned to the new authenticator.
     * @param authenticatorAddress The address of the new authenticator.
     * @param newAuthenticatorPubkey The public key of the new authenticator.
     * @param oldOffchainSignerCommitment The previous offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     */
    event AuthenticatorInserted(
        uint256 indexed leafIndex,
        uint32 pubkeyId,
        address indexed authenticatorAddress,
        uint256 indexed newAuthenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );

    /**
     * @dev Emitted when an authenticator is removed from a World ID account.
     * @param leafIndex The leaf index of the account in the Merkle tree.
     * @param pubkeyId The pubkey ID of the removed authenticator.
     * @param authenticatorAddress The address of the removed authenticator.
     * @param authenticatorPubkey The public key of the removed authenticator.
     * @param oldOffchainSignerCommitment The previous offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     */
    event AuthenticatorRemoved(
        uint256 indexed leafIndex,
        uint32 pubkeyId,
        address indexed authenticatorAddress,
        uint256 indexed authenticatorPubkey,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );

    /**
     * @dev Emitted when a new Merkle tree root is recorded.
     * @param root The new Merkle tree root.
     * @param timestamp The timestamp when the root was recorded.
     */
    event RootRecorded(uint256 indexed root, uint256 timestamp);

    /**
     * @dev Emitted when the root validity window is updated.
     * @param oldWindow The previous validity window in seconds.
     * @param newWindow The new validity window in seconds.
     */
    event RootValidityWindowUpdated(uint256 oldWindow, uint256 newWindow);

    /**
     * @dev Emitted when the maximum number of authenticators per account is updated.
     * @param oldMax The previous maximum number of authenticators.
     * @param newMax The new maximum number of authenticators.
     */
    event MaxAuthenticatorsUpdated(uint256 oldMax, uint256 newMax);

    /**
     * @dev Emitted when a recovery agent update is initiated.
     * @param leafIndex The leaf index of the account.
     * @param oldRecoveryAgent The current recovery agent.
     * @param newRecoveryAgent The new recovery agent to be set after cooldown.
     * @param executeAfter The timestamp after which the update can be executed.
     */
    event RecoveryAgentUpdateInitiated(
        uint256 indexed leafIndex,
        address indexed oldRecoveryAgent,
        address indexed newRecoveryAgent,
        uint256 executeAfter
    );

    /**
     * @dev Emitted when a recovery agent update is executed after cooldown.
     * @param leafIndex The leaf index of the account.
     * @param oldRecoveryAgent The previous recovery agent.
     * @param newRecoveryAgent The new recovery agent that was set.
     */
    event RecoveryAgentUpdateExecuted(
        uint256 indexed leafIndex, address indexed oldRecoveryAgent, address indexed newRecoveryAgent
    );

    /**
     * @dev Emitted when a pending recovery agent update is cancelled.
     * @param leafIndex The leaf index of the account.
     * @param cancelledRecoveryAgent The recovery agent update that was cancelled.
     */
    event RecoveryAgentUpdateCancelled(uint256 indexed leafIndex, address indexed cancelledRecoveryAgent);

    /**
     * @dev Emitted when the recovery agent update cooldown period is updated.
     * @param oldCooldown The previous cooldown period in seconds.
     * @param newCooldown The new cooldown period in seconds.
     */
    event RecoveryAgentUpdateCooldownUpdated(uint256 oldCooldown, uint256 newCooldown);

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
     * @dev Initiates a recovery agent update for a World ID account. The update will be pending for the cooldown period.
     * @param leafIndex The leaf index of the World ID account.
     * @param newRecoveryAgent The new recovery agent to set after cooldown.
     * @param signature The signature from an existing authenticator authorizing the update.
     * @param nonce The signature nonce for replay protection.
     */
    function initiateRecoveryAgentUpdate(
        uint256 leafIndex,
        address newRecoveryAgent,
        bytes memory signature,
        uint256 nonce
    ) external;

    /**
     * @dev Executes a pending recovery agent update after the cooldown period has elapsed. This
     *   function does not require a signature.
     * @param leafIndex The leaf index of the World ID account.
     */
    function executeRecoveryAgentUpdate(uint256 leafIndex) external;

    /**
     * @dev Cancels a pending recovery agent update. Can be called by any valid authenticator.
     * @param leafIndex The leaf index of the World ID account.
     * @param signature The signature from an existing authenticator authorizing the cancellation.
     * @param nonce The signature nonce for replay protection.
     */
    function cancelRecoveryAgentUpdate(uint256 leafIndex, bytes memory signature, uint256 nonce) external;

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
     * @dev Returns the recovery agent for the given World ID (based on its leaf index).
     * @param leafIndex The index of the leaf.
     */
    function getRecoveryAgent(uint256 leafIndex) external view returns (address);

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

    /**
     * @dev Returns the pending recovery agent update for a leaf index, if any.
     * @param leafIndex The leaf index to query.
     * @return newRecoveryAgent The new recovery agent address.
     * @return executeAfter The timestamp after which the update can be executed.
     */
    function getPendingRecoveryAgentUpdate(uint256 leafIndex)
        external
        view
        returns (address newRecoveryAgent, uint256 executeAfter);

    /**
     * @dev Returns the recovery agent update cooldown period in seconds.
     */
    function getRecoveryAgentUpdateCooldown() external view returns (uint256);

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

    /**
     * @dev Sets the cooldown period for recovery agent updates.
     */
    function setRecoveryAgentUpdateCooldown(uint256 newCooldown) external;
}
