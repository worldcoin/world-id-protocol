use alloy::primitives::Address;
use alloy::providers::DynProvider;
use eyre::Result;

use crate::bindings::IWorldIDSource;
use crate::primitives::KeccakChain;

/// Reads the current keccak chain state from a StateBridge contract.
pub async fn read_keccak_chain(
    provider: &DynProvider,
    bridge_address: Address,
) -> Result<KeccakChain> {
    let source = IWorldIDSource::new(bridge_address, provider);
    let chain = source.KECCAK_CHAIN().call().await?;
    Ok(KeccakChain::new(chain.head, chain.length))
}

/// Reads the latest root from a StateBridge contract.
pub async fn read_latest_root(
    provider: &DynProvider,
    bridge_address: Address,
) -> Result<alloy_primitives::U256> {
    let source = IWorldIDSource::new(bridge_address, provider);
    let root = source.LATEST_ROOT().call().await?;
    Ok(root)
}

/// Reads the contract version from a StateBridge contract.
pub async fn read_version(
    provider: &DynProvider,
    bridge_address: Address,
) -> Result<u8> {
    let source = IWorldIDSource::new(bridge_address, provider);
    let version = source.VERSION().call().await?;
    Ok(version)
}
