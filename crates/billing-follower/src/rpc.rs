//! [`ChainSource`] over JSON-RPC.

use std::{
    future::IntoFuture,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use alloy::{
    eips::BlockNumberOrTag,
    network::Ethereum,
    primitives::Address,
    providers::{Provider, RootProvider},
    rpc::{
        client::RpcClient,
        types::{Block, Filter, Log},
    },
    sol_types::SolEvent,
    transports::layers::RetryBackoffLayer,
};
use url::Url;
use world_id_primitives::rp::RpId;
use world_id_registries::world_id_billing::WorldIdBilling::{BilledRpUpdated, Registered};

use crate::source::{BillingEvent, BlockRef, ChainLog, ChainSource, EventSet, SourceError};

/// Bound on each JSON-RPC call, including the transport's own rate-limit retries.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Rate-limit retries the transport makes before a call fails.
const RATE_LIMIT_RETRIES: u32 = 3;
const RATE_LIMIT_BACKOFF_MS: u64 = 200;
/// The compute-unit budget the transport paces rate-limit retries against.
const COMPUTE_UNITS_PER_SECOND: u64 = 330;

/// Reads the Billing Contract over one or more JSON-RPC endpoints.
///
/// Calls go to one endpoint at a time, so consecutive reads see one node's view of the chain. A
/// failed call moves later calls to the next endpoint.
#[derive(Debug)]
pub struct RpcSource {
    providers: Vec<RootProvider<Ethereum>>,
    active: AtomicUsize,
    contract: Address,
}

impl RpcSource {
    /// Reads the Billing Contract at `contract` over the HTTP endpoints `urls`.
    ///
    /// # Panics
    /// If `urls` is empty.
    #[must_use]
    pub fn new(urls: Vec<Url>, contract: Address) -> Self {
        assert!(!urls.is_empty(), "RpcSource needs at least one endpoint");
        let providers = urls
            .into_iter()
            .map(|url| {
                let client = RpcClient::builder()
                    .layer(RetryBackoffLayer::new(
                        RATE_LIMIT_RETRIES,
                        RATE_LIMIT_BACKOFF_MS,
                        COMPUTE_UNITS_PER_SECOND,
                    ))
                    .http(url);
                RootProvider::new(client)
            })
            .collect();
        Self {
            providers,
            active: AtomicUsize::new(0),
            contract,
        }
    }

    /// The endpoint calls currently go to, and its index.
    fn pick(&self) -> (usize, &RootProvider<Ethereum>) {
        let index = self.active.load(Ordering::Relaxed) % self.providers.len();
        (index, &self.providers[index])
    }

    /// Awaits `call` on endpoint `index` within [`CALL_TIMEOUT`]. A failure moves later calls to
    /// the next endpoint.
    async fn guard<T, E>(
        &self,
        index: usize,
        method: &'static str,
        call: impl IntoFuture<Output = Result<T, E>>,
    ) -> Result<T, SourceError>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let error = match tokio::time::timeout(CALL_TIMEOUT, call.into_future()).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(error)) => SourceError::Rpc {
                method,
                source: Box::new(error),
            },
            Err(_) => SourceError::Timeout { method },
        };
        // Another call may have moved on already; only move off the endpoint that failed.
        let _ = self.active.compare_exchange(
            index,
            (index + 1) % self.providers.len(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        Err(error)
    }
}

impl ChainSource for RpcSource {
    async fn chain_id(&self) -> Result<u64, SourceError> {
        let (index, provider) = self.pick();
        self.guard(index, "eth_chainId", provider.get_chain_id())
            .await
    }

    async fn latest(&self) -> Result<BlockRef, SourceError> {
        let (index, provider) = self.pick();
        self.guard(
            index,
            "eth_getBlockByNumber",
            provider.get_block_by_number(BlockNumberOrTag::Latest),
        )
        .await?
        .map(|block| block_ref(&block))
        .ok_or_else(|| SourceError::Malformed {
            method: "eth_getBlockByNumber",
            reason: "no latest block".to_owned(),
        })
    }

    async fn block(&self, number: u64) -> Result<Option<BlockRef>, SourceError> {
        let (index, provider) = self.pick();
        Ok(self
            .guard(
                index,
                "eth_getBlockByNumber",
                provider.get_block_by_number(BlockNumberOrTag::Number(number)),
            )
            .await?
            .map(|block| block_ref(&block)))
    }

    async fn logs(
        &self,
        from: u64,
        to: u64,
        events: EventSet,
    ) -> Result<Vec<ChainLog>, SourceError> {
        let signatures = match events {
            EventSet::BilledRps => vec![BilledRpUpdated::SIGNATURE_HASH],
            EventSet::All => vec![BilledRpUpdated::SIGNATURE_HASH, Registered::SIGNATURE_HASH],
        };
        let filter = Filter::new()
            .address(self.contract)
            .from_block(from)
            .to_block(to)
            .event_signature(signatures);
        let (index, provider) = self.pick();
        let logs = self
            .guard(index, "eth_getLogs", provider.get_logs(&filter))
            .await?;
        let mut decoded = logs.iter().map(chain_log).collect::<Result<Vec<_>, _>>()?;
        decoded.sort_by_key(|log| (log.block_number, log.log_index));
        Ok(decoded)
    }
}

fn block_ref(block: &Block) -> BlockRef {
    BlockRef {
        number: block.header.inner.number,
        hash: block.header.hash,
        parent_hash: block.header.inner.parent_hash,
        timestamp: block.header.inner.timestamp,
    }
}

fn chain_log(log: &Log) -> Result<ChainLog, SourceError> {
    let malformed = |reason: &str| SourceError::Malformed {
        method: "eth_getLogs",
        reason: reason.to_owned(),
    };
    let (Some(block_number), Some(block_hash), Some(log_index)) =
        (log.block_number, log.block_hash, log.log_index)
    else {
        return Err(malformed("a log without its block or index"));
    };
    let event = match log.topic0() {
        Some(&Registered::SIGNATURE_HASH) => {
            let event = Registered::decode_log(&log.inner)
                .map_err(|_| malformed("an undecodable Registered log"))?
                .data;
            BillingEvent::Registered {
                rp_id: RpId::new(event.rpId),
                period_start: event.periodStart,
                nullifier: event.billingNullifier,
            }
        }
        Some(&BilledRpUpdated::SIGNATURE_HASH) => {
            let event = BilledRpUpdated::decode_log(&log.inner)
                .map_err(|_| malformed("an undecodable BilledRpUpdated log"))?
                .data;
            BillingEvent::BilledRpUpdated {
                rp_id: RpId::new(event.rpId),
                billed: event.billed,
            }
        }
        _ => return Err(malformed("a log of another event")),
    };
    Ok(ChainLog {
        block_number,
        block_hash,
        log_index,
        event,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::b256;

    /// `keccak256` of the event signatures in the Billing Contract's ABI.
    #[test]
    fn event_topics_match_the_contract() {
        assert_eq!(
            Registered::SIGNATURE_HASH,
            b256!("34db382174d785a7e95b8e462fc059aa18422a3ed86677e4904f85fefbc1fab1")
        );
        assert_eq!(Registered::SIGNATURE, "Registered(uint64,uint64,uint256)");
        assert_eq!(BilledRpUpdated::SIGNATURE, "BilledRpUpdated(uint64,bool)");
    }
}
