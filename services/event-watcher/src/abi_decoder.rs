use std::{collections::HashMap, sync::Arc};

use alloy::{
    dyn_abi::{DynSolValue, EventExt},
    json_abi::{Event, JsonAbi},
    primitives::{Address, B256},
    rpc::types::Log,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{config::ExplorerConfig, util};

/// All prepared event decoders for a single contract.
#[derive(Clone)]
pub struct PreparedContract {
    pub runtime_address: Address,
    pub abi_address: Address,
    /// Map from topic0 → decoder for each watched event.
    pub decoders: HashMap<B256, PreparedEvent>,
}

/// A single event decoder, ready to decode logs for that event.
#[derive(Clone)]
pub struct PreparedEvent {
    pub event_name: String,
    pub event_signature: String,
    pub topic0: B256,
    pub decoder: Arc<EventDecoder>,
}

#[derive(Clone)]
pub struct EventDecoder {
    event: Event,
}

#[derive(Debug, Error)]
pub enum AbiDecoderError {
    #[error("failed to fetch sourcecode for {address:#x}: {source}")]
    FetchSourcecode {
        address: Address,
        #[source]
        source: reqwest::Error,
    },
    #[error("failed to fetch abi for {address:#x}: {source}")]
    FetchAbi {
        address: Address,
        #[source]
        source: reqwest::Error,
    },
    #[error("explorer returned error for {address:#x}: {message}")]
    Explorer { address: Address, message: String },
    #[error("sourcecode response for {address:#x} did not contain a result")]
    MissingSourcecode { address: Address },
    #[error("proxy {proxy:#x} did not contain implementation address")]
    MissingImplementation { proxy: Address },
    #[error("invalid implementation address {value} for proxy {proxy:#x}")]
    InvalidImplementation { proxy: Address, value: String },
    #[error("failed to parse ABI for {address:#x}: {message}")]
    ParseAbi { address: Address, message: String },
    #[error("no events found in ABI for {address:#x}")]
    NoEventsFound { address: Address },
    #[error("no matching events after filter for {address:#x}")]
    NoMatchingEvents { address: Address },
    #[error("failed to decode log for event {event_signature}: {message}")]
    Decode {
        event_signature: String,
        message: String,
    },
}

#[derive(Deserialize)]
struct ExplorerResponse<T> {
    status: String,
    message: String,
    result: T,
}

#[derive(Debug, Deserialize)]
struct SourceCodeEntry {
    #[serde(rename = "Proxy")]
    proxy: String,
    #[serde(rename = "Implementation")]
    implementation: String,
}

impl EventDecoder {
    pub fn decode_log(&self, log: &Log) -> Result<Value, AbiDecoderError> {
        let decoded = self
            .event
            .decode_log(log.data())
            .map_err(|e| AbiDecoderError::Decode {
                event_signature: self.event.signature(),
                message: e.to_string(),
            })?;

        let mut fields = Map::new();
        let mut indexed_iter = decoded.indexed.iter();
        let mut body_iter = decoded.body.iter();

        for input in &self.event.inputs {
            let value = if input.indexed {
                indexed_iter.next()
            } else {
                body_iter.next()
            }
            .ok_or_else(|| AbiDecoderError::Decode {
                event_signature: self.event.signature(),
                message: format!("decoded value count mismatch for field {}", input.name),
            })?;

            let key = if input.name.is_empty() {
                if input.indexed {
                    format!("indexed_{}", fields.len())
                } else {
                    format!("field_{}", fields.len())
                }
            } else {
                input.name.clone()
            };
            fields.insert(key, dyn_value_to_json(value));
        }

        Ok(Value::Object(fields))
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch the ABI for a contract and prepare decoders for all (or filtered)
/// events.
///
/// If `event_names` is `Some`, only events whose `name` appears in the list
/// are included. If `None`, all events in the ABI are included.
pub async fn prepare_contract(
    client: &reqwest::Client,
    explorer: &ExplorerConfig,
    chain_id: u64,
    contract_address: Address,
    event_names: Option<&[String]>,
) -> Result<PreparedContract, AbiDecoderError> {
    let abi_address = resolve_abi_address(client, explorer, chain_id, contract_address).await?;

    let abi = fetch_abi(client, explorer, chain_id, abi_address).await?;

    let all_events: Vec<Event> = abi.events().cloned().collect();
    if all_events.is_empty() {
        return Err(AbiDecoderError::NoEventsFound {
            address: abi_address,
        });
    }

    let filtered: Vec<Event> = match event_names {
        Some(names) if !names.is_empty() => all_events
            .into_iter()
            .filter(|e| names.contains(&e.name))
            .collect(),
        _ => all_events,
    };

    if filtered.is_empty() {
        return Err(AbiDecoderError::NoMatchingEvents {
            address: abi_address,
        });
    }

    let mut decoders = HashMap::new();
    for event in filtered {
        let topic0 = event.selector();
        let prepared = PreparedEvent {
            event_name: event.name.clone(),
            event_signature: event.signature(),
            topic0,
            decoder: Arc::new(EventDecoder {
                event: event.clone(),
            }),
        };
        decoders.insert(topic0, prepared);
    }

    Ok(PreparedContract {
        runtime_address: contract_address,
        abi_address,
        decoders,
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

async fn resolve_abi_address(
    client: &reqwest::Client,
    explorer: &ExplorerConfig,
    chain_id: u64,
    address: Address,
) -> Result<Address, AbiDecoderError> {
    let response =
        call_explorer::<Vec<SourceCodeEntry>>(client, explorer, chain_id, address, "getsourcecode")
            .await
            .map_err(|e| match e {
                ExplorerCallError::Transport(source) => {
                    AbiDecoderError::FetchSourcecode { address, source }
                }
                ExplorerCallError::Explorer(message) => {
                    AbiDecoderError::Explorer { address, message }
                }
                ExplorerCallError::Parse(message) => AbiDecoderError::Explorer { address, message },
            })?;

    let Some(entry) = response.into_iter().next() else {
        return Err(AbiDecoderError::MissingSourcecode { address });
    };

    if entry.proxy == "1" {
        if entry.implementation.trim().is_empty() {
            return Err(AbiDecoderError::MissingImplementation { proxy: address });
        }
        let implementation =
            entry
                .implementation
                .parse()
                .map_err(|_| AbiDecoderError::InvalidImplementation {
                    proxy: address,
                    value: entry.implementation,
                })?;
        Ok(implementation)
    } else {
        Ok(address)
    }
}

async fn fetch_abi(
    client: &reqwest::Client,
    explorer: &ExplorerConfig,
    chain_id: u64,
    address: Address,
) -> Result<JsonAbi, AbiDecoderError> {
    let abi_json = call_explorer::<String>(client, explorer, chain_id, address, "getabi")
        .await
        .map_err(|e| match e {
            ExplorerCallError::Transport(source) => AbiDecoderError::FetchAbi { address, source },
            ExplorerCallError::Explorer(message) => AbiDecoderError::Explorer { address, message },
            ExplorerCallError::Parse(message) => AbiDecoderError::Explorer { address, message },
        })?;

    serde_json::from_str(&abi_json).map_err(|e| AbiDecoderError::ParseAbi {
        address,
        message: e.to_string(),
    })
}

#[derive(Debug, Error)]
enum ExplorerCallError {
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("{0}")]
    Explorer(String),
    #[error("{0}")]
    Parse(String),
}

/// Perform a single Explorer API call.
async fn call_explorer<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    explorer: &ExplorerConfig,
    chain_id: u64,
    address: Address,
    action: &str,
) -> Result<T, ExplorerCallError> {
    let mut params: Vec<(&str, String)> = vec![
        ("chainid", chain_id.to_string()),
        ("module", "contract".to_owned()),
        ("action", action.to_owned()),
        ("address", format!("{address:#x}")),
    ];
    if let Some(api_key) = &explorer.api_key {
        params.push(("apikey", api_key.clone()));
    }

    let response = client
        .get(&explorer.url)
        .query(&params)
        .send()
        .await
        .map_err(ExplorerCallError::Transport)?;

    let http_status = response.status();
    let body = response
        .text()
        .await
        .map_err(ExplorerCallError::Transport)?;

    if !http_status.is_success() {
        return Err(ExplorerCallError::Explorer(format!(
            "http status {http_status}: {body}"
        )));
    }

    let raw: ExplorerResponse<Value> = serde_json::from_str(&body).map_err(|e| {
        ExplorerCallError::Parse(format!("invalid explorer JSON: {e}; body={body}"))
    })?;

    if raw.status != "1" {
        return Err(ExplorerCallError::Explorer(format!(
            "status={} message={}",
            raw.status, raw.message,
        )));
    }

    let result: T = serde_json::from_value(raw.result).map_err(|e| {
        ExplorerCallError::Parse(format!("failed to deserialise explorer result: {e}"))
    })?;
    Ok(result)
}

fn dyn_value_to_json(value: &DynSolValue) -> Value {
    match value {
        DynSolValue::Bool(v) => Value::Bool(*v),
        DynSolValue::Int(v, _) => Value::String(v.to_string()),
        DynSolValue::Uint(v, _) => Value::String(v.to_string()),
        DynSolValue::Address(v) => util::address_to_value(*v),
        DynSolValue::FixedBytes(v, _) => Value::String(format!("0x{}", alloy::hex::encode(v))),
        DynSolValue::Bytes(v) => Value::String(format!("0x{}", alloy::hex::encode(v))),
        DynSolValue::String(v) => Value::String(v.clone()),
        DynSolValue::Array(values) | DynSolValue::FixedArray(values) => {
            Value::Array(values.iter().map(dyn_value_to_json).collect())
        }
        DynSolValue::Tuple(values) => Value::Array(values.iter().map(dyn_value_to_json).collect()),
        other => Value::String(format!("{other:?}")),
    }
}
