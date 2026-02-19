use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IWorldIDSource {
        struct Chain {
            bytes32 head;
            uint64 length;
        }

        struct Commitment {
            bytes32 blockHash;
            bytes data;
        }

        function propagateState(uint64[] calldata issuerSchemaIds, uint160[] calldata oprfKeyIds) external;

        function KECCAK_CHAIN() external view returns (Chain memory);

        event ChainCommitted(
            bytes32 indexed keccakChain,
            uint256 indexed blockNumber,
            uint256 indexed chainId,
            bytes commitment
        );
    }

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
    }

    #[sol(rpc)]
    interface IDisputeGameFactory {
        function gameCount() external view returns (uint256);
        function gameAtIndex(uint256 index) external view returns (
            uint32 gameType,
            uint256 timestamp,
            address proxy
        );
    }

    #[sol(rpc)]
    interface IDisputeGame {
        function status() external view returns (uint8);
        function rootClaim() external view returns (bytes32);
        function l2BlockNumber() external view returns (uint256);
        function extraData() external view returns (bytes memory);
    }

    #[sol(rpc)]
    interface ILightClientGateway {
        function head() external view returns (uint256);
        function headers(uint256 slot) external view returns (bytes32);
    }
}

/// ERC-7201 storage slot for the keccak chain head in StateBridge contracts.
/// `keccak256(abi.encode(uint256(keccak256("worldid.storage.WorldIDStateBridge")) - 1)) & ~bytes32(uint256(0xff))`
pub const STATE_BRIDGE_STORAGE_SLOT: alloy_primitives::B256 =
    alloy_primitives::b256!("8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00");

/// OP Stack L2ToL1MessagePasser predeploy address.
pub const L2_TO_L1_MESSAGE_PASSER: alloy_primitives::Address =
    alloy_primitives::address!("4200000000000000000000000000000000000016");
