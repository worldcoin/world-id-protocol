use alloy::sol;

// ── World ID Source (WorldIDSource.sol + StateBridge.sol + IStateBridge.sol) ──

sol! {
    #[sol(rpc)]
    interface IWorldIDSource {
        #[derive(Debug)]
        struct Chain {
            bytes32 head;
            uint64 length;
        }

        #[derive(Debug)]
        struct Commitment {
            bytes32 blockHash;
            bytes data;
        }

        #[derive(Debug)]
        struct Affine {
            uint256 x;
            uint256 y;
        }

        #[derive(Debug)]
        struct ProvenPubKeyInfo {
            Affine pubKey;
            bytes32 proofId;
        }

        #[derive(Debug)]
        struct ProvenRootInfo {
            uint256 timestamp;
            bytes32 proofId;
        }

        function propagateState(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds) external;
        function KECCAK_CHAIN() external view returns (Chain memory);
        function LATEST_ROOT() external view returns (uint256);
        function VERSION() external view returns (uint8);
        function issuerSchemaIdToPubkeyAndProofId(uint64 schemaId) external view returns (ProvenPubKeyInfo memory);
        function oprfKeyIdToPubkeyAndProofId(uint160 oprfKeyId) external view returns (ProvenPubKeyInfo memory);
        function rootToTimestampAndProofId(uint256 root) external view returns (ProvenRootInfo memory);

        event ChainCommitted(
            bytes32 indexed keccakChain,
            uint256 indexed blockNumber,
            uint256 indexed chainId,
            bytes commitment
        );

        event GatewayAdded(address indexed gateway);
        event GatewayRemoved(address indexed gateway);
    }
}

// ── ERC-7786 Gateway (Gateway.sol + IGateway.sol) ────────────────────────────

sol! {
    #[sol(rpc)]
    interface IGateway {
        function sendMessage(
            bytes calldata recipient,
            bytes calldata payload,
            bytes[] calldata attributes
        ) external payable returns (bytes32 sendId);

        function ATTRIBUTE() external view returns (bytes4);
        function STATE_BRIDGE() external view returns (address);
        function ANCHOR_BRIDGE() external view returns (address);
        function ANCHOR_CHAIN_ID() external view returns (uint256);
        function supportsAttribute(bytes4 selector) external view returns (bool);

        event MessageSent(
            bytes32 indexed sendId,
            bytes sender,
            bytes recipient,
            bytes payload,
            uint256 value,
            bytes[] attributes
        );
    }
}

// ── World ID Satellite (WorldIDSatellite.sol + IWorldID.sol) ─────────────────

sol! {
    #[sol(rpc)]
    interface IWorldIDSatellite {
        function verify(
            uint256 nullifier,
            uint256 action,
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;

        function verifySession(
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256 sessionId,
            uint256[2] calldata sessionNullifier,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;

        function verifyProofAndSignals(
            uint256 nullifier,
            uint256 action,
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256 sessionId,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;

        function isValidRoot(uint256 root) external view returns (bool);

        function VERIFIER() external view returns (address);
        function MIN_EXPIRATION_THRESHOLD() external view returns (uint64);
        function ROOT_VALIDITY_WINDOW() external view returns (uint256);
        function TREE_DEPTH() external view returns (uint256);

        function addGateway(address gateway) external;
        function removeGateway(address gateway) external;

        function VERSION() external view returns (uint8);
        function KECCAK_CHAIN() external view returns (bytes32 head, uint64 length);
        function LATEST_ROOT() external view returns (uint256);
        function issuerSchemaIdToPubkeyAndProofId(uint64 schemaId) external view returns (uint256 pubKeyX, uint256 pubKeyY, bytes32 proofId);
        function oprfKeyIdToPubkeyAndProofId(uint160 oprfKeyId) external view returns (uint256 pubKeyX, uint256 pubKeyY, bytes32 proofId);
        function rootToTimestampAndProofId(uint256 root) external view returns (uint256 timestamp, bytes32 proofId);
    }
}

// ── Permissioned Gateway Adapter (PermissionedGatewayAdapter.sol) ────────────

sol! {
    #[sol(rpc)]
    interface IPermissionedGatewayAdapter {
        function sendMessage(
            bytes calldata recipient,
            bytes calldata payload,
            bytes[] calldata attributes
        ) external payable returns (bytes32 sendId);

        function ATTRIBUTE() external view returns (bytes4);
        function STATE_BRIDGE() external view returns (address);
        function ANCHOR_BRIDGE() external view returns (address);
        function ANCHOR_CHAIN_ID() external view returns (uint256);
        function supportsAttribute(bytes4 selector) external view returns (bool);
        function owner() external view returns (address);
    }
}

// ── Ethereum MPT Gateway Adapter (EthereumMPTGatewayAdapter.sol) ─────────────

sol! {
    #[sol(rpc)]
    interface IEthereumMPTGatewayAdapter {
        function sendMessage(
            bytes calldata recipient,
            bytes calldata payload,
            bytes[] calldata attributes
        ) external payable returns (bytes32 sendId);

        function ATTRIBUTE() external view returns (bytes4);
        function STATE_BRIDGE() external view returns (address);
        function ANCHOR_BRIDGE() external view returns (address);
        function ANCHOR_CHAIN_ID() external view returns (uint256);
        function supportsAttribute(bytes4 selector) external view returns (bool);
        function owner() external view returns (address);

        function DISPUTE_GAME_FACTORY() external view returns (address);
        function requireFinalized() external view returns (bool);
        function setRequireFinalized(bool required) external;
    }
}

// ── Dispute Game Factory + Dispute Game (OP Stack) ───────────────────────────

sol! {
    #[sol(rpc)]
    interface IDisputeGameFactory {
        function gameCount() external view returns (uint256);
        function gameAtIndex(uint256 index) external view returns (
            uint32 gameType,
            uint256 timestamp,
            address proxy
        );
        function games(
            uint32 gameType,
            bytes32 rootClaim,
            bytes calldata extraData
        ) external view returns (address proxy, uint256 timestamp);
    }

    #[sol(rpc)]
    interface IDisputeGame {
        function status() external view returns (uint8);
        function rootClaim() external view returns (bytes32);
        function l2BlockNumber() external view returns (uint256);
        function extraData() external view returns (bytes memory);
    }
}

// ── Light Client Gateway Adapter (LightClientGatewayAdapter.sol) ─────────────

sol! {
    #[derive(Debug)]
    struct StorageSlot {
        bytes32 key;
        bytes32 value;
    }

    #[derive(Debug)]
    struct ProofOutputs {
        bytes32 prevHeader;
        uint256 prevHead;
        bytes32 prevSyncCommitteeHash;
        uint256 newHead;
        bytes32 newHeader;
        bytes32 executionStateRoot;
        uint256 executionBlockNumber;
        bytes32 syncCommitteeHash;
        bytes32 nextSyncCommitteeHash;
        StorageSlot[] storageSlots;
    }

    #[sol(rpc)]
    interface ILightClientGatewayAdapter {
        function sendMessage(
            bytes calldata recipient,
            bytes calldata payload,
            bytes[] calldata attributes
        ) external payable returns (bytes32 sendId);

        function ATTRIBUTE() external view returns (bytes4);
        function STATE_BRIDGE() external view returns (address);
        function ANCHOR_BRIDGE() external view returns (address);
        function ANCHOR_CHAIN_ID() external view returns (uint256);
        function supportsAttribute(bytes4 selector) external view returns (bool);
        function owner() external view returns (address);

        function verifier() external view returns (address);
        function programVKey() external view returns (bytes32);
        function head() external view returns (uint256);
        function headers(uint256 slot) external view returns (bytes32);
        function syncCommitteeHashes(uint256 period) external view returns (bytes32);

        function setVerifier(address newVerifier) external;
        function setProgramVKey(bytes32 newVKey) external;
        function setSyncCommitteeHash(uint256 period, bytes32 hash) external;

        event LightClientUpdated(uint256 indexed slot, bytes32 executionStateRoot);
        event SyncCommitteeUpdated(uint256 indexed period, bytes32 syncCommitteeHash);
        event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
        event ProgramVKeyUpdated(bytes32 indexed oldVKey, bytes32 indexed newVKey);
    }
}

// ── World Chain Registry Interfaces ──────────────────────────────────────────

sol! {
    #[sol(rpc)]
    interface IWorldIDRegistry {
        function getLatestRoot() external view returns (uint256);

        event RootRecorded(uint256 indexed root, uint256 timestamp);
    }

    #[sol(rpc)]
    interface ICredentialSchemaIssuerRegistry {
        #[derive(Debug)]
        struct Pubkey {
            uint256 x;
            uint256 y;
        }

        event IssuerSchemaRegistered(uint64 indexed issuerSchemaId, Pubkey pubkey, address signer, uint160 oprfKeyId);
        event IssuerSchemaRemoved(uint64 indexed issuerSchemaId, Pubkey pubkey, address signer);
        event IssuerSchemaPubkeyUpdated(uint64 indexed issuerSchemaId, Pubkey oldPubkey, Pubkey newPubkey);
        event IssuerSchemaSignerUpdated(uint64 indexed issuerSchemaId, address oldSigner, address newSigner);
        event IssuerSchemaUpdated(uint64 indexed issuerSchemaId, string oldSchemaUri, string newSchemaUri);

        function issuerSchemaIdToPubkey(uint64 issuerSchemaId) external view returns (Pubkey memory);
    }

    #[sol(rpc)]
    interface IOprfKeyRegistry {
        #[derive(Debug)]
        struct OprfPublicKey {
            uint256 x;
            uint256 y;
        }

        #[derive(Debug)]
        struct RegisteredOprfPublicKey {
            OprfPublicKey key;
            uint256 epoch;
        }

        function getOprfPublicKeyAndEpoch(uint160 oprfKeyId) external view returns (RegisteredOprfPublicKey memory);

        event SecretGenFinalize(uint160 indexed oprfKeyId, uint32 indexed epoch);
    }
}

// ── RP Registry (RpRegistry.sol) ─────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    interface IRpRegistry {
        event RpRegistered(
            uint64 indexed rpId,
            uint160 indexed oprfKeyId,
            address manager,
            string unverifiedWellKnownDomain
        );

        event RpUpdated(
            uint64 indexed rpId,
            uint160 indexed oprfKeyId,
            bool active,
            address manager,
            address signer,
            string unverifiedWellKnownDomain
        );
    }
}

// ── Custom Errors (Error.sol) ────────────────────────────────────────────────

sol! {
    error EmptyChainedCommits();
    error NothingChanged();
    error ZeroAddress();
    error ExpirationTooOld();
    error InvalidMerkleRoot();
    error UnregisteredIssuerSchemaId();
    error UnregisteredOprfKeyId();
    error InvalidRecipientResponse();
    error InvalidRecipient();
    error EmptyPayload();
    error InvalidAttribute();
    error UnsupportedAttribute(bytes4 selector);
    error InvalidOutputRoot();
    error GameNotFinalized();
    error SlotBehindHead();
    error NonCheckpointSlot();
    error SyncCommitteeNotSet();
    error NextSyncCommitteeMismatch();
    error InvalidCommitmentSelector(bytes4 selector);
    error EmptyAccountProof();
    error InvalidAccountField();
    error StorageValueTooLarge();
    error InvalidChainHead();
    error InvalidContractName();
    error InvalidContractVersion();
    error InvalidRootValidityWindow();
    error InvalidTreeDepth();
    error InvalidMinExpirationThreshold();
}

// ── Constants ────────────────────────────────────────────────────────────────

/// ERC-7201 storage slot for the keccak chain head in StateBridge contracts.
/// `keccak256(abi.encode(uint256(keccak256("worldid.storage.WorldIDStateBridge")) - 1)) & ~bytes32(uint256(0xff))`
pub const STATE_BRIDGE_STORAGE_SLOT: alloy_primitives::B256 =
    alloy_primitives::b256!("8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00");

/// OP Stack L2ToL1MessagePasser predeploy address.
pub const L2_TO_L1_MESSAGE_PASSER: alloy_primitives::Address =
    alloy_primitives::address!("4200000000000000000000000000000000000016");
