mod ethereum_mpt;

pub use ethereum_mpt::EthereumMptSatellite;
use tracing::Instrument;

use std::{future::Future, pin::Pin, sync::Arc};

use alloy::primitives::{Address, B256, Bytes};
use eyre::Result;

use crate::{
    log::SourceStateLog,
    primitives::{ChainCommitment, reduce},
};

/// A destination chain that can receive bridged World ID state.
#[auto_impl::auto_impl(Box, Arc, &)]
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
    #[allow(clippy::type_complexity)]
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

pub fn spawn_satellite(
    satellite: impl Satellite + 'static,
    log: Arc<SourceStateLog>,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
    Box::pin(async move {
        let span = tracing::info_span!(
            "satellite",
            name = satellite.name(),
            chain_id = satellite.chain_id(),
        );

        let mut chain_head = log.subscribe();
        let mut local_head = B256::ZERO;

        async {
            loop {
                chain_head.changed().await?;

                let delta = match log.since(local_head) {
                    Some(d) if !d.is_empty() => d,
                    _ => continue,
                };

                let count = delta.len();
                let merged = reduce(&delta)?;
                let target_head = merged.chain_head;

                tracing::debug!(
                    commitments = count,
                    target = %target_head,
                    "relaying delta"
                );

                match satellite.relay(&merged).await {
                    Ok(tx_hash) => {
                        local_head = target_head;
                        tracing::info!(%tx_hash, head = %local_head, "relay succeeded");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "relay failed, will retry on next head");
                    }
                }
            }
        }
        .instrument(span)
        .await
    })
}
