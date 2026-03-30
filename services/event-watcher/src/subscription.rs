use std::time::Instant;

use alloy::{
    primitives::B256,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
};
use futures_util::StreamExt;
use serde_json::Value as JsonValue;
use tokio::sync::watch;

use crate::{
    abi_decoder::{self, PreparedContract},
    config::{ContractConfig, ExplorerConfig, ServiceConfig},
    metrics,
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

/// Single-shot attempt: fetch ABI if not cached → connect WS → subscribe → stream events.
///
/// Returns `Ok(())` on clean shutdown, `Err` on any failure. The caller owns the retry
/// loop and the `prepared` cache — passing `&mut Option<PreparedContract>` lets a
/// successfully-fetched ABI survive across retries without being re-fetched.
pub async fn run_contract_subscription(
    runtime: &ContractRuntime,
    prepared: &mut Option<PreparedContract>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), SubscriptionError> {
    let contract_name = &runtime.contract.name;

    if *shutdown.borrow() {
        tracing::info!(contract_name, "subscription shutdown requested");
        return Ok(());
    }

    // 1. Fetch ABI if not already cached.
    if prepared.is_none() {
        let http = reqwest::Client::new();
        let event_names_ref = runtime.contract.event_names.as_deref();

        let p = abi_decoder::prepare_contract(
            &http,
            &runtime.explorer,
            runtime.chain_id,
            runtime.contract.contract_address,
            event_names_ref,
        )
        .await
        .map_err(|e| SubscriptionError::AbiFetch(e.to_string()))?;

        let event_list: Vec<&str> = p.decoders.values().map(|d| d.event_name.as_str()).collect();
        tracing::info!(
            contract_name,
            abi_address = %format!("{:#x}", p.abi_address),
            event_count = p.decoders.len(),
            events = ?event_list,
            "prepared contract decoder"
        );
        *prepared = Some(p);
    }
    let cached = prepared.as_ref().unwrap();

    // 2. Connect WS provider.
    let provider = connect_provider(&runtime.ws_rpc_url).await?;

    // 3. Subscribe to logs.
    let topic0s: Vec<B256> = cached.decoders.keys().copied().collect();
    let filter = Filter::new()
        .address(runtime.contract.contract_address)
        .event_signature(topic0s);

    let event_names: Vec<&str> = cached
        .decoders
        .values()
        .map(|d| d.event_name.as_str())
        .collect();
    tracing::info!(
        contract_name,
        contract_address = %format!("{:#x}", runtime.contract.contract_address),
        event_count = cached.decoders.len(),
        events = ?event_names,
        "subscription established"
    );

    let sub = provider
        .subscribe_logs(&filter)
        .await
        .map_err(|e| SubscriptionError::Subscribe(e.to_string()))?;
    let started_at = Instant::now();
    metrics::set_connected(contract_name, true);
    metrics::set_subscription_uptime(contract_name, 0.0);

    // 4. Stream events until stream closes or shutdown signal.
    let mut stream = sub.into_stream();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    metrics::set_connected(contract_name, false);
                    tracing::info!(contract_name, "subscription shutdown requested");
                    return Ok(());
                }
            }
            maybe_log = stream.next() => {
                let Some(log) = maybe_log else {
                    return Err(SubscriptionError::StreamClosed);
                };

                handle_log(runtime, cached, started_at, log);
            }
        }
    }
}

fn handle_log(
    runtime: &ContractRuntime,
    prepared: &PreparedContract,
    started_at: Instant,
    log: alloy::rpc::types::Log,
) {
    let contract_name = &runtime.contract.name;

    metrics::set_subscription_uptime(contract_name, started_at.elapsed().as_secs_f64());

    if log.removed {
        metrics::increment_events_dropped_removed(contract_name);
        tracing::warn!(
            contract_name,
            tx_hash = ?log.transaction_hash,
            log_index = ?log.log_index,
            "removed log ignored"
        );
        return;
    }

    // Match topic0 to find the right decoder.
    let topic0 = log.topic0().copied();

    let Some(topic0) = topic0 else {
        tracing::warn!(
            contract_name,
            tx_hash = ?log.transaction_hash,
            "log has no topic0; skipping"
        );
        return;
    };

    let Some(prepared_event) = prepared.decoders.get(&topic0) else {
        tracing::warn!(
            contract_name,
            topic0 = %format!("{topic0:#x}"),
            tx_hash = ?log.transaction_hash,
            "no decoder for topic0; skipping"
        );
        return;
    };

    let fields = match prepared_event.decoder.decode_log(&log) {
        Ok(JsonValue::Object(fields)) => fields,
        Ok(other) => {
            metrics::increment_decode_error(contract_name, &prepared_event.event_name);
            tracing::warn!(
                contract_name,
                event_name = prepared_event.event_name,
                decoded = %other,
                tx_hash = ?log.transaction_hash,
                "decoded log fields were not an object; skipping"
            );
            return;
        }
        Err(e) => {
            metrics::increment_decode_error(contract_name, &prepared_event.event_name);
            tracing::warn!(
                contract_name,
                event_name = prepared_event.event_name,
                error = ?e,
                tx_hash = ?log.transaction_hash,
                "failed to decode log; skipping"
            );
            return;
        }
    };

    emit_event_log(runtime, prepared, prepared_event, &log, fields);

    if let Some(block_number) = log.block_number {
        metrics::set_last_event_block(contract_name, &prepared_event.event_name, block_number);
    }
    metrics::increment_events_emitted(contract_name, &prepared_event.event_name);
}

fn emit_event_log(
    runtime: &ContractRuntime,
    prepared: &PreparedContract,
    prepared_event: &crate::abi_decoder::PreparedEvent,
    log: &alloy::rpc::types::Log,
    fields: serde_json::Map<String, JsonValue>,
) {
    tracing::info!(
        message = "observed on-chain event",
        chain_name = runtime.chain_name,
        chain_id = runtime.chain_id,
        name = runtime.contract.name,
        contract_address = %format!("{:#x}", runtime.contract.contract_address),
        abi_address = %format!("{:#x}", prepared.abi_address),
        event_name = prepared_event.event_name,
        event_signature = prepared_event.event_signature,
        block_number = ?log.block_number,
        block_hash = ?log.block_hash,
        tx_hash = ?log.transaction_hash,
        log_index = ?log.log_index,
        fields = %JsonValue::Object(fields),
        "observed on-chain event"
    );
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
    #[error("failed to fetch ABI: {0}")]
    AbiFetch(String),
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
            Self::AbiFetch(_) => "abi_fetch_failed",
            Self::Connect { .. } => "connect_failed",
            Self::Subscribe(_) => "subscribe_failed",
            Self::StreamClosed => "stream_closed",
        }
    }
}
