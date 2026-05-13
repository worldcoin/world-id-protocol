//! Whether the WorldIDRegistry proxy is pointing at V1 or V2. Probed once at
//! startup; not updated at runtime. The gateway is rolling-restarted after a
//! contract upgrade so pods re-probe.

use std::sync::Arc;

use alloy::{contract::Error as ContractError, primitives::Address, providers::DynProvider};
use tracing::{info, warn};
use world_id_registries::world_id::WorldIdRegistryV2::WorldIdRegistryV2Instance;

use crate::error::{GatewayError, GatewayResult};

fn http_only_run_mode() -> bool {
    std::env::var("RUN_MODE")
        .is_ok_and(|value| matches!(value.to_ascii_lowercase().as_str(), "http" | "http-only"))
}

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
    match v2.MAX_AUTHENTICATORS_V2_HARD_LIMIT().call().await {
        Ok(_) => {
            info!("registry version detected: V2");
            Ok(RegistryVersion::V2)
        }
        Err(err) if is_v2_selector_unavailable(&err) => {
            warn!(error = ?err, "V2 selector unavailable; defaulting to V1");
            Ok(RegistryVersion::V1)
        }
        Err(err) => {
            if http_only_run_mode() {
                warn!(
                    error = ?err,
                    "registry version probe failed in http-only mode; defaulting to V1"
                );
                Ok(RegistryVersion::V1)
            } else {
                warn!(error = ?err, "registry version probe failed");
                Err(GatewayError::Config(format!(
                    "failed to probe registry version: {err}"
                )))
            }
        }
    }
}

fn is_v2_selector_unavailable(err: &ContractError) -> bool {
    matches!(err, ContractError::ZeroData(_, _)) || err.as_revert_data().is_some()
}
