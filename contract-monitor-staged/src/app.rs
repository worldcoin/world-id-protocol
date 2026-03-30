use tokio::sync::watch;

use crate::{
    abi_decoder::PreparedContract,
    config::AppConfig,
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
            contract,
        };

        handles.push(tokio::spawn(run_subscription_loop(
            runtime,
            shutdown_rx.clone(),
        )));
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

async fn run_subscription_loop(runtime: ContractRuntime, shutdown_rx: watch::Receiver<bool>) {
    let contract_name = runtime.contract.name.clone();

    // Persisted across retries: ABI is not re-fetched once successfully cached.
    let mut prepared: Option<PreparedContract> = None;

    loop {
        match run_contract_subscription(&runtime, &mut prepared, shutdown_rx.clone()).await {
            Ok(()) => break, // clean shutdown
            Err(e) => {
                let reason = e.reason();

                tracing::warn!(
                    name = contract_name,
                    reason,
                    error = ?e,
                    "subscription attempt failed; will retry"
                );

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                // Loop again — `prepared` is preserved if ABI was already fetched.
            }
        }
    }
}
