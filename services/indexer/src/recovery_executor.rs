//! Background scheduler that calls `executeRecoveryAgentUpdate` on-chain
//! for pending recovery agent updates whose cooldown has elapsed.
//!
//! Gated behind the `RECOVERY_EXECUTOR_ENABLED` env var (default `false`).
//! Requires `RECOVERY_EXECUTOR_PRIVATE_KEY` for signing transactions.

use std::time::Duration;

use alloy::{
    network::EthereumWallet, primitives::Address, providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use url::Url;
use world_id_core::world_id_registry::WorldIdRegistry;

use crate::db::DB;

/// Configuration for the recovery executor scheduler.
#[derive(Debug, Clone)]
pub struct RecoveryExecutorConfig {
    /// Whether the recovery executor is enabled.
    pub enabled: bool,
    /// Private key hex string for signing transactions.
    pub private_key: Option<String>,
}

impl RecoveryExecutorConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("RECOVERY_EXECUTOR_ENABLED")
            .ok()
            .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
            .unwrap_or(false);

        let private_key = std::env::var("RECOVERY_EXECUTOR_PRIVATE_KEY").ok();

        Self {
            enabled,
            private_key,
        }
    }
}

/// How often to poll for ready updates.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum number of pending updates to process per poll cycle.
const BATCH_LIMIT: i64 = 50;

/// Base backoff duration for retries after failure.
const BASE_BACKOFF: Duration = Duration::from_secs(5);

/// Maximum number of consecutive failures before increasing poll interval.
const MAX_CONSECUTIVE_FAILURES: u32 = 10;

/// Run the recovery executor background loop.
///
/// This loop polls the `pending_recovery_agent_updates` table for rows with
/// `status = 'pending' AND execute_after <= now()`, then calls
/// `executeRecoveryAgentUpdate(leafIndex)` on-chain for each.
///
/// On success: increments `attempts` and sets `last_attempt_at`. The `status`
/// transitions to `'executed'` only when the on-chain `RecoveryAgentUpdateExecuted`
/// event is indexed by the event processor.
///
/// On failure: increments `attempts`, logs error, and backs off.
pub async fn run_recovery_executor(
    db: DB,
    rpc_url: Url,
    registry_address: Address,
    config: RecoveryExecutorConfig,
) -> eyre::Result<()> {
    let private_key_hex = config.private_key.ok_or_else(|| {
        eyre::eyre!("RECOVERY_EXECUTOR_PRIVATE_KEY is required when RECOVERY_EXECUTOR_ENABLED=true")
    })?;

    let signer: PrivateKeySigner = private_key_hex
        .parse()
        .map_err(|e| eyre::eyre!("Failed to parse RECOVERY_EXECUTOR_PRIVATE_KEY: {}", e))?;

    let wallet = EthereumWallet::from(signer);

    // Build a provider with the wallet signer attached
    let signing_provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    let registry = WorldIdRegistry::new(registry_address, &signing_provider);

    tracing::info!("🟢 Recovery executor started");

    let mut consecutive_failures: u32 = 0;

    loop {
        let poll_delay = if consecutive_failures > MAX_CONSECUTIVE_FAILURES {
            POLL_INTERVAL + BASE_BACKOFF * consecutive_failures
        } else {
            POLL_INTERVAL
        };

        tokio::time::sleep(poll_delay).await;

        let ready_updates = match db
            .pending_recovery_agent_updates()
            .get_ready_for_execution(BATCH_LIMIT)
            .await
        {
            Ok(updates) => updates,
            Err(e) => {
                tracing::error!(error = %e, "Failed to query pending recovery agent updates");
                consecutive_failures = consecutive_failures.saturating_add(1);
                continue;
            }
        };

        if ready_updates.is_empty() {
            consecutive_failures = 0;
            continue;
        }

        tracing::info!(
            count = ready_updates.len(),
            "Processing pending recovery agent updates"
        );

        let mut had_failure = false;

        for update in ready_updates {
            // Record the attempt first
            if let Err(e) = db
                .pending_recovery_agent_updates()
                .record_attempt(update.leaf_index)
                .await
            {
                tracing::error!(
                    leaf_index = update.leaf_index,
                    error = %e,
                    "Failed to record execution attempt"
                );
                had_failure = true;
                continue;
            }

            // Call executeRecoveryAgentUpdate on-chain
            tracing::info!(
                leaf_index = update.leaf_index,
                new_recovery_agent = %update.new_recovery_agent,
                attempt = update.attempts + 1,
                "Executing recovery agent update on-chain"
            );

            match registry
                .executeRecoveryAgentUpdate(update.leaf_index)
                .send()
                .await
            {
                Ok(pending_tx) => {
                    match pending_tx.watch().await {
                        Ok(_receipt) => {
                            tracing::info!(
                                leaf_index = update.leaf_index,
                                "Recovery agent update transaction confirmed"
                            );
                            // Status transitions to 'executed' when the on-chain event is indexed
                        }
                        Err(e) => {
                            tracing::error!(
                                leaf_index = update.leaf_index,
                                error = %e,
                                "Recovery agent update transaction failed to confirm"
                            );
                            had_failure = true;
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        leaf_index = update.leaf_index,
                        attempt = update.attempts + 1,
                        error = %e,
                        "Failed to send executeRecoveryAgentUpdate transaction"
                    );
                    had_failure = true;
                }
            }
        }

        if had_failure {
            consecutive_failures = consecutive_failures.saturating_add(1);
        } else {
            consecutive_failures = 0;
        }
    }
}
