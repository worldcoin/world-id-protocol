use alloy::sol;

// ── Shared types (standalone, not duplicated in any interface block) ─────────

sol! {
    /// A block commitment.
    #[derive(Debug)]
    struct Commitment {
        bytes32 blockHash;
        bytes data;
    }
}

// ── World ID Source (WorldIDSource.sol) ───────────────────────────────────────
//
// Wrapped in a Rust module so the struct names match the Solidity ABI exactly
// (`InitConfig`, `Chain`, etc.) without conflicting with other sol! blocks.

pub mod source {
    use alloy::sol;

    sol! {
        #[derive(Debug)]
        struct InitConfig {
            string name;
            string version;
            address owner;
            address[] authorizedGateways;
        }

        #[derive(Debug)]
        struct Chain {
            bytes32 head;
            uint64 length;
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

        #[sol(rpc)]
        interface IWorldIDSource {
            function initialize(InitConfig memory cfg) external;
            function propagateState(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds) external;
            function LATEST_ROOT() external view returns (uint256);
            function KECCAK_CHAIN() external view returns (Chain memory);
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
}

// ── World ID Satellite (WorldIDSatellite.sol) ────────────────────────────────

pub mod satellite {
    use alloy::sol;

    sol! {
        #[derive(Debug)]
        struct InitConfig {
            string name;
            string version;
            address owner;
            address[] authorizedGateways;
        }

        #[sol(rpc)]
        interface IWorldIDSatellite {
            function initialize(InitConfig memory cfg) external;
            function addGateway(address gateway) external;
            function removeGateway(address gateway) external;
            function isValidRoot(uint256 root) external view returns (bool);

            function LATEST_ROOT() external view returns (uint256);
            function KECCAK_CHAIN() external view returns (bytes32 head, uint64 length);
            function VERSION() external view returns (uint8);
            function issuerSchemaIdToPubkeyAndProofId(uint64 schemaId) external view returns (uint256 pubKeyX, uint256 pubKeyY, bytes32 proofId);
            function oprfKeyIdToPubkeyAndProofId(uint160 oprfKeyId) external view returns (uint256 pubKeyX, uint256 pubKeyY, bytes32 proofId);
            function rootToTimestampAndProofId(uint256 root) external view returns (uint256 timestamp, bytes32 proofId);

            function VERIFIER() external view returns (address);
            function MIN_EXPIRATION_THRESHOLD() external view returns (uint64);
            function ROOT_VALIDITY_WINDOW() external view returns (uint256);
            function TREE_DEPTH() external view returns (uint256);
        }
    }
}

// ── World Chain Registry Interfaces ──────────────────────────────────────────

sol! {
    #[sol(rpc)]
    interface IWorldIDRegistry {
        function getLatestRoot() external view returns (uint256);
        function initialize(uint256 treeDepth, address feeRecipient, address feeToken, uint256 fee) external;
        function createAccount(
            address recoveryAddress,
            address[] calldata authenticatorAddresses,
            uint256[] calldata authenticatorPubkeys,
            uint256 offchainSignerCommitment
        ) external;

        event RootRecorded(uint256 indexed root, uint256 timestamp);
    }
}

sol! {
    #[sol(rpc)]
    interface ICredentialSchemaIssuerRegistry {
        #[derive(Debug)]
        struct Pubkey {
            uint256 x;
            uint256 y;
        }

        function issuerSchemaIdToPubkey(uint64 issuerSchemaId) external view returns (Pubkey memory);
        function initialize(address feeRecipient, address feeToken, uint256 fee, address oprfKeyRegistry) external;
        function register(uint64 issuerSchemaId, Pubkey memory pubkey, address signer) external returns (uint256);

        event IssuerSchemaRegistered(uint64 indexed issuerSchemaId, Pubkey pubkey, address signer, uint160 oprfKeyId);
        event IssuerSchemaRemoved(uint64 indexed issuerSchemaId, Pubkey pubkey, address signer);
    }
}

sol! {
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
        function initialize(address owner, address keygenAdmin, address verifier, uint16 threshold, uint16 numPeers) external;
        function registerOprfPeers(address[] calldata peers) external;
    }
}

// ── Gateway Adapters ─────────────────────────────────────────────────────────

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

// ── Mock DisputeGame contracts (for E2E relay testing) ───────────────────────

sol! {
    /// Mutable mock dispute game exposing all getters the relay needs.
    #[sol(rpc)]
    interface IRelayMockDisputeGame {
        function setStatus(uint8 s) external;
        function setRootClaim(bytes32 rc) external;
        function setL2BlockNumber(uint256 bn) external;
        function setExtraData(bytes calldata ed) external;

        function status() external view returns (uint8);
        function rootClaim() external view returns (bytes32);
        function l2BlockNumber() external view returns (uint256);
        function extraData() external view returns (bytes memory);
    }

    /// Mock factory supporting gameCount/gameAtIndex for the relay scanner,
    /// plus games() for on-chain gateway verification.
    #[sol(rpc)]
    interface IRelayMockDisputeGameFactory {
        function addGame(uint32 gameType, address proxy) external;
        function gameCount() external view returns (uint256);
        function gameAtIndex(uint256 index) external view returns (uint32 gameType, uint256 timestamp, address proxy);
        function games(uint32 gameType, bytes32 rootClaim, bytes calldata extraData) external view returns (address proxy, uint64 timestamp);
    }
}

// ── Constants ────────────────────────────────────────────────────────────────

/// ERC-7201 storage slot for the keccak chain head in StateBridge contracts.
/// `keccak256(abi.encode(uint256(keccak256("worldid.storage.WorldIDStateBridge")) - 1)) & ~bytes32(uint256(0xff))`
pub const STATE_BRIDGE_STORAGE_SLOT: alloy_primitives::B256 =
    alloy_primitives::b256!("8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00");
