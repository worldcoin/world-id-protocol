use std::time::Duration;

use backon::BackoffBuilder;
use backon::ExponentialBuilder;
use tokio::sync::watch;

use crate::{
    abi_decoder::PreparedContract,
    config::AppConfig,
    metrics,
    subscription::{ContractRuntime, run_contract_subscription},
};

pub async fn run(config: AppConfig) -> eyre::Result<()> {
    tracing::info!(
        chain_name = config.chain_name,
        chain_id = config.chain_id,
        ws_rpc_url = config.ws_rpc_url,
        explorer_url = config.explorer.url,
        contract_count = config.contracts.len(),
        "loaded watcher config"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut handles = Vec::new();

    for contract in config.contracts.iter().cloned() {
        tracing::info!(
            name = contract.name,
            contract_address = %format!("{:#x}", contract.contract_address),
            event_names = ?contract.event_names,
            "spawning contract task"
        );

        let runtime = ContractRuntime {
            chain_name: config.chain_name.clone(),
            chain_id: config.chain_id,
            ws_rpc_url: config.ws_rpc_url.clone(),
            explorer: config.explorer.clone(),
            service: config.service.clone(),
            contract,
        };

        handles.push(spawn_runner(runtime, shutdown_rx.clone()));
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

fn spawn_runner(
    runtime: ContractRuntime,
    shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let contract_name = runtime.contract.name.clone();

        let mut backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(
                runtime.service.reconnect_initial_backoff_ms,
            ))
            .with_max_delay(Duration::from_millis(
                runtime.service.reconnect_max_backoff_ms,
            ))
            .with_jitter()
            .without_max_times()
            .build();

        // Persisted across retries: ABI is not re-fetched once successfully cached.
        let mut prepared: Option<PreparedContract> = None;

        loop {
            match run_contract_subscription(&runtime, &mut prepared, shutdown_rx.clone()).await {
                Ok(()) => break, // clean shutdown
                Err(e) => {
                    let reason = e.reason();
                    metrics::set_connected(&contract_name, false);
                    metrics::set_subscription_uptime(&contract_name, 0.0);
                    metrics::increment_reconnect(&contract_name, reason);

                    tracing::warn!(
                        name = contract_name,
                        reason,
                        error = ?e,
                        "subscription attempt failed; will retry"
                    );

                    if let Some(delay) = backoff.next() {
                        tokio::time::sleep(delay).await;
                    }
                    // Loop again — `prepared` is preserved if ABI was already fetched.
                }
            }
        }
    })
}
