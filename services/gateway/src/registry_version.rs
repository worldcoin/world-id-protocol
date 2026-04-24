//! Whether the WorldIDRegistry proxy is pointing at V1 or V2. Probed once at
//! startup; not updated at runtime. The gateway is rolling-restarted after a
//! contract upgrade so pods re-probe.

use std::sync::Arc;

use alloy::{primitives::Address, providers::DynProvider};
use tracing::debug;
use world_id_core::world_id_registry::WorldIdRegistryV2::WorldIdRegistryV2Instance;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryVersion {
    V1,
    V2,
}

/// Probes `MAX_AUTHENTICATORS_V2_HARD_LIMIT()` — a V2-only public constant (WIP-104).
/// Success → V2. Any error (revert, unknown selector, transport failure) → V1.
pub async fn probe(provider: Arc<DynProvider>, proxy_addr: Address) -> RegistryVersion {
    let v2 = WorldIdRegistryV2Instance::new(proxy_addr, provider);
    match v2.MAX_AUTHENTICATORS_V2_HARD_LIMIT().call().await {
        Ok(_) => RegistryVersion::V2,
        Err(err) => {
            debug!(error = ?err, "V2 selector probe failed; treating proxy as V1");
            RegistryVersion::V1
        }
    }
}
