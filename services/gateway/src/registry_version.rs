//! Whether the WorldIDRegistry proxy is pointing at V1 or V2. Probed once at
//! startup; not updated at runtime. The gateway is rolling-restarted after a
//! contract upgrade so pods re-probe.

use std::sync::Arc;

use alloy::{primitives::Address, providers::DynProvider};
use tracing::debug;
use world_id_core::world_id_registry::{
    WorldIdRegistry::WorldIdRegistryInstance, WorldIdRegistryV2::WorldIdRegistryV2Instance,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryVersion {
    V1,
    V2,
}

/// Probes `MAX_AUTHENTICATORS_V2_HARD_LIMIT()` — a V2-only public constant (WIP-104).
/// Success → V2. V2 selector failure → confirm the proxy is reachable through a
/// V1 view, retry the V2 selector once, then fall back to V1.
///
/// This avoids permanently selecting V1 at startup when the initial V2 probe
/// failed due to a transient RPC/transport issue rather than an unknown selector.
pub async fn probe(
    provider: Arc<DynProvider>,
    proxy_addr: Address,
) -> Result<RegistryVersion, String> {
    let v2 = WorldIdRegistryV2Instance::new(proxy_addr, provider.clone());
    match v2.MAX_AUTHENTICATORS_V2_HARD_LIMIT().call().await {
        Ok(_) => Ok(RegistryVersion::V2),
        Err(first_v2_err) => {
            debug!(error = ?first_v2_err, "initial V2 selector probe failed");

            let v1 = WorldIdRegistryInstance::new(proxy_addr, provider);
            v1.getMaxAuthenticators()
                .call()
                .await
                .map_err(|v1_err| {
                    format!(
                        "registry version probe failed: V2 selector error: {first_v2_err}; V1 reachability error: {v1_err}"
                    )
                })?;

            match v2.MAX_AUTHENTICATORS_V2_HARD_LIMIT().call().await {
                Ok(_) => Ok(RegistryVersion::V2),
                Err(second_v2_err) => {
                    debug!(
                        first_error = ?first_v2_err,
                        second_error = ?second_v2_err,
                        "V2 selector probe failed twice while V1 view succeeded; treating proxy as V1"
                    );
                    Ok(RegistryVersion::V1)
                }
            }
        }
    }
}
