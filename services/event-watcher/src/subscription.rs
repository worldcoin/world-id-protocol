use std::time::{Duration, Instant};

use alloy::{
    primitives::B256,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
};
use backon::{Backoff, BackoffBuilder, ExponentialBuilder};
use futures_util::StreamExt;
use serde_json::{Map, Value};
use tokio::sync::watch;

use crate::{
    abi_decoder::{self, PreparedContract},
    config::{ContractConfig, ExplorerConfig, ServiceConfig},
    metrics, util,
};

#[derive(Clone)]
pub struct ContractRuntime {
    pub chain_name: String,
    pub chain_id: u64,
    pub ws_rpc_url: String,
    pub explorer: ExplorerConfig,
    pub service: ServiceConfig,
    pub contract: ContractConfig,
}

pub async fn run_contract_subscription(
    runtime: ContractRuntime,
    mut shutdown: watch::Receiver<bool>,
) -> eyre::Result<()> {
    let contract_name = runtime.contract.name.clone();
    let mut backoff = build_backoff(&runtime.service);

    // Lazily fetched and cached across reconnect iterations.
    let mut prepared: Option<PreparedContract> = None;

    loop {
        if *shutdown.borrow() {
            tracing::info!(contract_name, "subscription shutdown requested");
            return Ok(());
        }

        // 1. Fetch ABI if not already cached.
        if prepared.is_none() {
            let http = reqwest::Client::new();
            let event_names_ref = runtime.contract.event_names.as_deref();

            match abi_decoder::prepare_contract(
                &http,
                &runtime.explorer,
                runtime.chain_id,
                runtime.contract.contract_address,
                event_names_ref,
            )
            .await
            {
                Ok(p) => {
                    let event_list: Vec<&str> =
                        p.decoders.values().map(|d| d.event_name.as_str()).collect();
                    tracing::info!(
                        contract_name,
                        abi_address = %format!("{:#x}", p.abi_address),
                        event_count = p.decoders.len(),
                        events = ?event_list,
                        "prepared contract decoder"
                    );
                    prepared = Some(p);
                }
                Err(e) => {
                    let delay = backoff.next().unwrap_or(Duration::from_millis(
                        runtime.service.reconnect_max_backoff_ms,
                    ));
                    tracing::warn!(
                        contract_name,
                        backoff_ms = delay.as_millis() as u64,
                        error = ?e,
                        "ABI fetch failed; retrying"
                    );

                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                tracing::info!(contract_name, "subscription shutdown requested");
                                return Ok(());
                            }
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                    continue;
                }
            }
        }
        let cached = prepared.as_ref().unwrap();

        // 2. Open WS subscription, stream events.
        match connect_and_run(&runtime, cached, &mut shutdown).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                let reason = error.reason();
                metrics::set_connected(&contract_name, false);
                metrics::set_subscription_uptime(&contract_name, 0.0);
                metrics::increment_reconnect(&contract_name, reason);

                let delay = backoff.next().unwrap_or(Duration::from_millis(
                    runtime.service.reconnect_max_backoff_ms,
                ));

                tracing::warn!(
                    contract_name,
                    reason,
                    backoff_ms = delay.as_millis() as u64,
                    error = ?error,
                    "subscription loop failed; reconnecting"
                );

                // Don't clear `prepared` — keep the ABI cached.
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(contract_name, "subscription shutdown requested");
                            return Ok(());
                        }
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

fn build_backoff(service: &ServiceConfig) -> impl Backoff {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(service.reconnect_initial_backoff_ms))
        .with_max_delay(Duration::from_millis(service.reconnect_max_backoff_ms))
        .with_jitter()
        .without_max_times()
        .build()
}

async fn connect_and_run(
    runtime: &ContractRuntime,
    prepared: &PreparedContract,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), SubscriptionError> {
    let provider = connect_provider(&runtime.ws_rpc_url).await?;

    // Build the multi-topic0 filter for this contract.
    let topic0s: Vec<B256> = prepared.decoders.keys().copied().collect();
    let filter = Filter::new()
        .address(runtime.contract.contract_address)
        .event_signature(topic0s.clone());

    let event_names: Vec<&str> = prepared
        .decoders
        .values()
        .map(|d| d.event_name.as_str())
        .collect();
    tracing::info!(
        contract_name = runtime.contract.name,
        contract_address = %format!("{:#x}", runtime.contract.contract_address),
        event_count = prepared.decoders.len(),
        events = ?event_names,
        "subscription established"
    );

    let sub = provider
        .subscribe_logs(&filter)
        .await
        .map_err(|e| SubscriptionError::Subscribe(e.to_string()))?;
    let started_at = Instant::now();
    metrics::set_connected(&runtime.contract.name, true);
    metrics::set_subscription_uptime(&runtime.contract.name, 0.0);

    let mut stream = sub.into_stream();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    metrics::set_connected(&runtime.contract.name, false);
                    return Ok(());
                }
            }
            maybe_log = stream.next() => {
                let Some(log) = maybe_log else {
                    return Err(SubscriptionError::StreamClosed);
                };

                metrics::set_subscription_uptime(
                    &runtime.contract.name,
                    started_at.elapsed().as_secs_f64(),
                );

                if log.removed {
                    metrics::increment_events_dropped_removed(&runtime.contract.name);
                    tracing::warn!(
                        contract_name = runtime.contract.name,
                        tx_hash = ?log.transaction_hash,
                        log_index = ?log.log_index,
                        "removed log ignored"
                    );
                    continue;
                }

                // Match topic0 to find the right decoder.
                let topic0 = log
                    .topic0()
                    .copied();

                let Some(topic0) = topic0 else {
                    tracing::warn!(
                        contract_name = runtime.contract.name,
                        tx_hash = ?log.transaction_hash,
                        "log has no topic0; skipping"
                    );
                    continue;
                };

                let Some(prepared_event) = prepared.decoders.get(&topic0) else {
                    tracing::warn!(
                        contract_name = runtime.contract.name,
                        topic0 = %format!("{topic0:#x}"),
                        tx_hash = ?log.transaction_hash,
                        "no decoder for topic0; skipping"
                    );
                    continue;
                };

                let fields = match prepared_event.decoder.decode_log(&log) {
                    Ok(f) => f,
                    Err(e) => {
                        metrics::increment_decode_error(
                            &runtime.contract.name,
                            &prepared_event.event_name,
                        );
                        tracing::warn!(
                            contract_name = runtime.contract.name,
                            event_name = prepared_event.event_name,
                            error = ?e,
                            tx_hash = ?log.transaction_hash,
                            "failed to decode log; skipping"
                        );
                        continue;
                    }
                };

                emit_event_log(runtime, prepared, prepared_event, &log, fields);

                if let Some(block_number) = log.block_number {
                    metrics::set_last_event_block(
                        &runtime.contract.name,
                        &prepared_event.event_name,
                        block_number,
                    );
                }
                metrics::increment_events_emitted(
                    &runtime.contract.name,
                    &prepared_event.event_name,
                );
            }
        }
    }
}

fn emit_event_log(
    runtime: &ContractRuntime,
    prepared: &PreparedContract,
    prepared_event: &crate::abi_decoder::PreparedEvent,
    log: &alloy::rpc::types::Log,
    fields: Value,
) {
    let mut event = Map::new();
    util::insert_string(&mut event, "message", "observed on-chain event");
    util::insert_string(&mut event, "service", "world-id-event-watcher");
    util::insert_string(&mut event, "chain_name", runtime.chain_name.clone());
    util::insert_u64(&mut event, "chain_id", runtime.chain_id);
    util::insert_string(&mut event, "name", runtime.contract.name.clone());
    util::insert_string(&mut event, "event_name", prepared_event.event_name.clone());
    util::insert_string(
        &mut event,
        "contract_address",
        format!("{:#x}", runtime.contract.contract_address),
    );
    util::insert_string(
        &mut event,
        "abi_address",
        format!("{:#x}", prepared.abi_address),
    );
    util::insert_string(
        &mut event,
        "event_signature",
        prepared_event.event_signature.clone(),
    );
    if let Some(block_number) = log.block_number {
        util::insert_u64(&mut event, "block_number", block_number);
    }
    if let Some(block_hash) = log.block_hash {
        util::insert_string(&mut event, "block_hash", format!("{block_hash:#x}"));
    }
    if let Some(tx_hash) = log.transaction_hash {
        util::insert_string(&mut event, "tx_hash", format!("{tx_hash:#x}"));
    }
    if let Some(log_index) = log.log_index {
        util::insert_u64(&mut event, "log_index", log_index);
    }
    event.insert("fields".to_owned(), fields);

    let event_json = Value::Object(event);
    tracing::info!(event = %event_json, "observed on-chain event");
}

async fn connect_provider(url: &str) -> Result<DynProvider, SubscriptionError> {
    let ws_connect = WsConnect::new(url).with_max_retries(0);
    ProviderBuilder::new()
        .connect_ws(ws_connect)
        .await
        .map(|p| p.erased())
        .map_err(|error| SubscriptionError::Connect {
            url: url.to_owned(),
            error: error.to_string(),
        })
}

#[derive(Debug, thiserror::Error)]
pub enum SubscriptionError {
    #[error("failed to connect websocket provider to {url}: {error}")]
    Connect { url: String, error: String },
    #[error("failed to subscribe to logs: {0}")]
    Subscribe(String),
    #[error("subscription stream closed")]
    StreamClosed,
}

impl SubscriptionError {
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Connect { .. } => "connect_failed",
            Self::Subscribe(_) => "subscribe_failed",
            Self::StreamClosed => "stream_closed",
        }
    }
}
