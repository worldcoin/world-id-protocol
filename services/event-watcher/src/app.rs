use tokio::sync::watch;

use crate::{
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
        if !contract.enabled {
            tracing::info!(
                name = contract.name,
                contract_address = %format!("{:#x}", contract.contract_address),
                "contract disabled; skipping"
            );
            continue;
        }

        tracing::info!(
            name = contract.name,
            contract_address = %format!("{:#x}", contract.contract_address),
            event_names = ?contract.event_names,
            "spawning contract task (ABI will be fetched lazily)"
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
        loop {
            match run_contract_subscription(runtime.clone(), shutdown_rx.clone()).await {
                Ok(()) => break,
                Err(error) => {
                    metrics::increment_watcher_restart(&contract_name);
                    tracing::error!(name = contract_name, error = ?error, "contract subscription task exited unexpectedly; restarting");
                }
            }
        }
    })
}
