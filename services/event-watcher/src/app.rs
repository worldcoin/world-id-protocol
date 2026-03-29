use reqwest::Client;
use tokio::sync::watch;

use crate::{
    abi_decoder::prepare_contract,
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

    let http = Client::builder().build()?;
    let mut runtimes = Vec::new();

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
            "preparing contract decoder"
        );

        let event_names_ref = contract.event_names.as_deref();
        let prepared = prepare_contract(
            &http,
            &config.explorer,
            config.chain_id,
            contract.contract_address,
            event_names_ref,
        )
        .await?;

        let event_list: Vec<&str> = prepared
            .decoders
            .values()
            .map(|d| d.event_name.as_str())
            .collect();
        tracing::info!(
            name = contract.name,
            abi_address = %format!("{:#x}", prepared.abi_address),
            event_count = prepared.decoders.len(),
            events = ?event_list,
            "prepared contract decoder"
        );

        runtimes.push(ContractRuntime {
            chain_name: config.chain_name.clone(),
            chain_id: config.chain_id,
            ws_rpc_url: config.ws_rpc_url.clone(),
            service: config.service.clone(),
            contract,
            prepared,
        });
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut handles = Vec::new();
    for runtime in runtimes {
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
