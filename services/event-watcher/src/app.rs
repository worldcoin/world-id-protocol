use reqwest::Client;
use tokio::sync::watch;

use crate::{
    abi_decoder::prepare_decoder,
    config::AppConfig,
    metrics,
    subscription::{SubscriptionRuntime, run_subscription},
};

pub async fn run(config: AppConfig) -> eyre::Result<()> {
    tracing::info!(
        chain_name = config.chain_name,
        chain_id = config.chain_id,
        ws_rpc_url = config.ws_rpc_url,
        explorer_url = config.explorer.url,
        subscription_count = config.subscriptions.len(),
        "loaded watcher config"
    );

    let http = Client::builder().build()?;
    let mut runtimes = Vec::new();
    for subscription in config.subscriptions.iter().cloned() {
        tracing::info!(
            name = subscription.name,
            contract_address = %format!("{:#x}", subscription.contract_address),
            event_signature = subscription.event_signature,
            "preparing subscription decoder"
        );
        let prepared = prepare_decoder(
            &http,
            &config.explorer,
            config.chain_id,
            subscription.contract_address,
            &subscription.event_signature,
        )
        .await?;
        tracing::info!(
            name = subscription.name,
            abi_address = %format!("{:#x}", prepared.abi_address),
            event_name = prepared.event_name,
            topic0 = %format!("{:#x}", prepared.topic0),
            "prepared subscription decoder"
        );
        runtimes.push(SubscriptionRuntime {
            chain_name: config.chain_name.clone(),
            chain_id: config.chain_id,
            ws_rpc_url: config.ws_rpc_url.clone(),
            service: config.service.clone(),
            subscription,
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
    runtime: SubscriptionRuntime,
    shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let name = runtime.subscription.name.clone();
        loop {
            match run_subscription(runtime.clone(), shutdown_rx.clone()).await {
                Ok(()) => break,
                Err(error) => {
                    metrics::increment_watcher_restart(&name);
                    tracing::error!(name, error = ?error, "subscription task exited unexpectedly; restarting");
                }
            }
        }
    })
}
