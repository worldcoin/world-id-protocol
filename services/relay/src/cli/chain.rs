use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use world_id_services_common::ProviderArgs;

/// ERC-7201 storage slot for the keccak chain head in StateBridge contracts.
/// `keccak256(abi.encode(uint256(keccak256("worldid.storage.WorldIDStateBridge")) - 1)) & ~bytes32(uint256(0xff))`
pub const STATE_BRIDGE_STORAGE_SLOT: alloy_primitives::B256 =
    alloy_primitives::b256!("8ea751544b8bbcbc8929c26e76fb7b6c3629dd0f7da849a522d50f1a3c170d00");

/// OP Stack L2ToL1MessagePasser predeploy address.
pub const L2_TO_L1_MESSAGE_PASSER: alloy_primitives::Address =
    alloy_primitives::address!("4200000000000000000000000000000000000016");

#[derive(Debug, Clone, Deserialize)]
pub enum Gateway {
    EthereumMPT,
    Helios,
    Permissioned,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceChain {
    pub world_id_source: Address,
    pub credential_issuer_schema_registry: Address,
    pub oprf_key_registry: Address,
    pub provider: ProviderArgs,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnchorChainChain {
    pub gateway: Address,
    pub satellite: Address,
    pub dispute_game_factory: Address,
    pub require_finalized: bool,
    pub supported_attributes: Vec<Gateway>,
    pub provider: ProviderArgs,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SatelliteChainBuilder {
    pub satellite: Address,
    pub gateway: Address,
    pub supported_attributes: Vec<Gateway>,
    pub provider: ProviderArgs,
}
