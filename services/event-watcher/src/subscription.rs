use std::time::{Duration, Instant};

use alloy::{
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
};
use backon::{Backoff, BackoffBuilder, ExponentialBuilder};
use futures_util::StreamExt;
use serde_json::{Map, Value};
use tokio::sync::watch;

use crate::{
    abi_decoder::PreparedSubscription,
    config::{ServiceConfig, SubscriptionConfig},
    metrics, util,
};

#[derive(Clone)]
pub struct SubscriptionRuntime {
    pub chain_name: String,
    pub chain_id: u64,
    pub ws_rpc_url: String,
    pub service: ServiceConfig,
    pub subscription: SubscriptionConfig,
    pub prepared: PreparedSubscription,
}

pub async fn run_subscription(
    runtime: SubscriptionRuntime,
    mut shutdown: watch::Receiver<bool>,
) -> eyre::Result<()> {
    let event_name = runtime.prepared.event_name.clone();
    let mut backoff = build_backoff(&runtime.service);

    loop {
        if *shutdown.borrow() {
            tracing::info!(event_name, "subscription shutdown requested");
            return Ok(());
        }

        match connect_and_run(&runtime, &mut shutdown).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                let reason = error.reason();
                metrics::set_connected(&event_name, false);
                metrics::set_subscription_uptime(&event_name, 0.0);
                metrics::increment_reconnect(&event_name, reason);

                // Fetch the next delay; `without_max_times()` means this
                // iterator never returns `None`, but fall back defensively.
                let delay = backoff.next().unwrap_or(Duration::from_millis(
                    runtime.service.reconnect_max_backoff_ms,
                ));

                tracing::warn!(
                    event_name,
                    reason,
                    backoff_ms = delay.as_millis() as u64,
                    error = ?error,
                    "subscription loop failed; reconnecting"
                );

                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(event_name, "subscription shutdown requested");
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
    runtime: &SubscriptionRuntime,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), SubscriptionError> {
    let provider = connect_provider(&runtime.ws_rpc_url).await?;
    let filter = Filter::new()
        .address(runtime.subscription.contract_address)
        .event_signature(runtime.prepared.topic0);

    tracing::info!(
        event_name = runtime.prepared.event_name,
        contract_address = %format!("{:#x}", runtime.subscription.contract_address),
        event_signature = runtime.subscription.event_signature,
        topic0 = %format!("{:#x}", runtime.prepared.topic0),
        "subscription established"
    );

    let sub = provider
        .subscribe_logs(&filter)
        .await
        .map_err(|e| SubscriptionError::Subscribe(e.to_string()))?;
    let started_at = Instant::now();
    metrics::set_connected(&runtime.prepared.event_name, true);
    metrics::set_subscription_uptime(&runtime.prepared.event_name, 0.0);

    let mut stream = sub.into_stream();
    let uptime_event_name = runtime.prepared.event_name.clone();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    metrics::set_connected(&runtime.prepared.event_name, false);
                    return Ok(());
                }
            }
            maybe_log = stream.next() => {
                let Some(log) = maybe_log else {
                    return Err(SubscriptionError::StreamClosed);
                };

                metrics::set_subscription_uptime(&uptime_event_name, started_at.elapsed().as_secs_f64());

                if log.removed {
                    metrics::increment_events_dropped_removed(&runtime.prepared.event_name);
                    tracing::warn!(event_name = runtime.prepared.event_name, tx_hash = ?log.transaction_hash, log_index = ?log.log_index, "removed log ignored");
                    continue;
                }

                let fields = match runtime.prepared.decoder.decode_log(&log) {
                    Ok(f) => f,
                    Err(e) => {
                        metrics::increment_decode_error(&runtime.prepared.event_name);
                        tracing::warn!(
                            event_name = runtime.prepared.event_name,
                            error = ?e,
                            tx_hash = ?log.transaction_hash,
                            "failed to decode log; skipping"
                        );
                        continue;
                    }
                };
                emit_event_log(runtime, &log, fields);
                if let Some(block_number) = log.block_number {
                    metrics::set_last_event_block(&runtime.prepared.event_name, block_number);
                }
                metrics::increment_events_emitted(&runtime.prepared.event_name);
            }
        }
    }
}

fn emit_event_log(runtime: &SubscriptionRuntime, log: &alloy::rpc::types::Log, fields: Value) {
    let mut event = Map::new();
    util::insert_string(&mut event, "message", "observed on-chain event");
    util::insert_string(&mut event, "service", "world-id-event-watcher");
    util::insert_string(&mut event, "chain_name", runtime.chain_name.clone());
    util::insert_u64(&mut event, "chain_id", runtime.chain_id);
    util::insert_string(
        &mut event,
        "event_name",
        runtime.prepared.event_name.clone(),
    );
    util::insert_string(
        &mut event,
        "contract_address",
        format!("{:#x}", runtime.subscription.contract_address),
    );
    util::insert_string(
        &mut event,
        "abi_address",
        format!("{:#x}", runtime.prepared.abi_address),
    );
    util::insert_string(
        &mut event,
        "event_signature",
        runtime.subscription.event_signature.clone(),
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
