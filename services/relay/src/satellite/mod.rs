mod ethereum_mpt;
mod permissioned;

pub use ethereum_mpt::EthereumMptSatellite;
pub use permissioned::PermissionedSatellite;

use std::{future::Future, pin::Pin};

use alloy::primitives::{Address, Bytes, B256};
use eyre::Result;

use crate::proof::ChainCommitment;

/// A destination chain that can receive bridged World ID state.
///
/// Different satellites use different proof strategies (permissioned, MPT, ZK light client)
/// but all ultimately deliver commitments to a `WorldIDSatellite` contract via an ERC-7786
/// gateway.
///
/// This trait is object-safe so it can be used as `dyn Satellite`. Async methods return
/// boxed futures to support dynamic dispatch.
pub trait Satellite: Send + Sync {
    /// Human-readable name for logging (e.g. "ethereum-mainnet", "base-sepolia").
    fn name(&self) -> &str;

    /// The chain ID of this destination.
    fn chain_id(&self) -> u64;

    /// The gateway contract address on this destination chain.
    fn gateway(&self) -> Address;

    /// The satellite (bridge) contract address on this destination chain.
    fn bridge(&self) -> Address;

    /// Build the proof attributes for the given commitment.
    ///
    /// Returns `(attribute, payload)` ready for `gateway.sendMessage()`.
    fn build_proof<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<(Bytes, Bytes)>> + Send + 'a>>;

    /// Send the relay transaction to the destination chain.
    ///
    /// The default pattern is to call [`build_proof`](Satellite::build_proof) and then
    /// forward the result to [`relay::send_relay_tx`](crate::relay::send_relay_tx).
    fn relay<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>>;
}
