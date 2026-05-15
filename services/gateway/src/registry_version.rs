//! Whether the WorldIDRegistry proxy is pointing at V1 or V2. Probed once at
//! startup; not updated at runtime. The gateway is rolling-restarted after a
//! contract upgrade so pods re-probe.

use std::sync::Arc;

use alloy::{primitives::Address, providers::DynProvider};
use tracing::{info, warn};
use world_id_registries::world_id::WorldIdRegistryV2::WorldIdRegistryV2Instance;

use crate::error::{GatewayError, GatewayResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryVersion {
    V1,
    V2,
}

/// Probes `MAX_AUTHENTICATORS_V2_HARD_LIMIT()` — a V2-only public constant (WIP-104).
/// Success means V2.
pub async fn probe(
    provider: Arc<DynProvider>,
    proxy_addr: Address,
) -> GatewayResult<RegistryVersion> {
    let v2 = WorldIdRegistryV2Instance::new(proxy_addr, provider);

    //  Call constant available on v1 and v2 to check connection
    if let Err(err) = v2.MAX_AUTHENTICATORS_HARD_LIMIT().call().await {
        warn!(error = ?err, "registry baseline probe failed");
        return Err(GatewayError::Config(format!(
            "failed to probe registry version: baseline selector failed: {err}"
        )));
    }

    // Call v2 function to assess if upgrade happened
    match v2.MAX_AUTHENTICATORS_V2_HARD_LIMIT().call().await {
        Ok(_) => {
            info!("registry version detected: V2");
            Ok(RegistryVersion::V2)
        }
        Err(err) => {
            warn!(error = ?err, "V2 selector unavailable; defaulting to V1");
            Ok(RegistryVersion::V1)
        }
    }
}

#[cfg(test)]
mod tests {
    use world_id_test_utils::anvil::TestAnvil;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_detects_v1_on_anvil_registry_proxy() {
        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
        let registry_addr = anvil
            .deploy_world_id_registry(deployer)
            .await
            .expect("failed to deploy WorldIDRegistry");
        let provider = Arc::new(anvil.provider().expect("failed to build anvil provider"));

        assert_eq!(
            probe(provider, registry_addr).await.unwrap(),
            RegistryVersion::V1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_detects_v2_on_anvil_registry_proxy() {
        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
        let registry_addr = anvil
            .deploy_world_id_registry_v2(deployer)
            .await
            .expect("failed to deploy WorldIDRegistry V2");
        let provider = Arc::new(anvil.provider().expect("failed to build anvil provider"));

        assert_eq!(
            probe(provider, registry_addr).await.unwrap(),
            RegistryVersion::V2
        );
    }
}
