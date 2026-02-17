use std::time::Duration;

use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use world_id_core::world_id_registry::WorldIdRegistry;

use tracing::instrument;

use crate::{error::IndexerResult, tree::TreeState};

/// Periodically checks that the local in-memory Merkle root remains valid on-chain.
#[instrument(level = "info", skip_all, fields(%registry, interval_secs))]
pub async fn root_sanity_check_loop(
    rpc_url: String,
    registry: Address,
    interval_secs: u64,
    tree_state: TreeState,
) -> IndexerResult<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().expect("invalid RPC URL"));
    let contract = WorldIdRegistry::new(registry, provider.clone());

    tracing::info!(
        registry = %registry,
        interval_secs,
        "Starting periodic Merkle root sanity checker"
    );

    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        let local_root = tree_state.root().await;

        // Check validity window on-chain first (covers slight lag vs current root)
        let is_valid = match contract.isValidRoot(local_root).call().await {
            Ok(v) => v,
            Err(err) => {
                tracing::error!(?err, "failed to call isValidRoot");
                continue;
            }
        };

        if !is_valid {
            // Fetch current on-chain root for diagnostics
            let current_onchain_root = match contract.currentRoot().call().await {
                Ok(r) => r,
                Err(err) => {
                    tracing::error!(?err, "failed to call currentRoot");
                    U256::ZERO
                }
            };

            tracing::error!(
                local_root = %format!("0x{:x}", local_root),
                current_onchain_root = %format!("0x{:x}", current_onchain_root),
                "Local Merkle root is not valid on-chain"
            );
            return Err(crate::tree::TreeError::RootMismatch {
                actual: format!("0x{:x}", local_root),
                expected: format!("0x{:x}", current_onchain_root),
            }
            .into());
        } else {
            tracing::debug!(local_root = %format!("0x{:x}", local_root), "Local Merkle root is valid on-chain");
        }
    }
}
