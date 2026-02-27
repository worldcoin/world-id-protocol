use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::DynProvider;
use eyre::Result;
use futures::stream::BoxStream;
use futures_util::StreamExt;
use tracing::{error, info, warn};

use crate::proof::merge_commitments;
use crate::satellite::Satellite;
use crate::{propagate, stream};

// ── Registry change types ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RegistryChange {
    Issuer(u64),
    OprfKey(u64),
    RpRegistration(u64),
}

#[derive(Debug, Default)]
pub struct PendingChanges {
    pub issuer_schema_ids: HashSet<u64>,
    pub oprf_key_ids: HashSet<u64>,
}

impl PendingChanges {
    pub fn is_empty(&self) -> bool {
        self.issuer_schema_ids.is_empty() && self.oprf_key_ids.is_empty()
    }

    pub fn clear(&mut self) {
        self.issuer_schema_ids.clear();
        self.oprf_key_ids.clear();
    }

    pub fn drain_ids(&mut self) -> (Vec<u64>, Vec<u64>) {
        (
            self.issuer_schema_ids.drain().collect(),
            self.oprf_key_ids.drain().collect(),
        )
    }

    fn apply(&mut self, change: RegistryChange) {
        match change {
            RegistryChange::Issuer(id) => {
                self.issuer_schema_ids.insert(id);
            }
            RegistryChange::OprfKey(id) | RegistryChange::RpRegistration(id) => {
                self.oprf_key_ids.insert(id);
            }
        }
    }
}

// ── Engine ───────────────────────────────────────────────────────────────────

pub struct WcRegistries {
    pub source: Address,
    pub issuer_registry: Address,
    pub oprf_registry: Address,
    pub rp_registry: Address,
}

/// Maximum number of `ChainCommitted` events to merge into a single relay batch.
const MAX_COMMITMENT_BATCH: usize = 64;

/// The core relay engine.
///
/// `ChainCommitted` events are batched over a configurable window, merged
/// into a single combined `Commitment[]` payload, then stream-mapped through
/// each satellite's proof builder and relayed concurrently.
pub struct Engine {
    wc_provider: DynProvider,
    registries: WcRegistries,
    satellites: Vec<Arc<dyn Satellite>>,
    batch_interval: Duration,
    /// How long to accumulate `ChainCommitted` events before merging and relaying.
    commitment_batch_window: Duration,
}

impl Engine {
    pub fn new(
        wc_provider: DynProvider,
        registries: WcRegistries,
        satellites: Vec<Arc<dyn Satellite>>,
        batch_interval: Duration,
        commitment_batch_window: Duration,
    ) -> Self {
        Self {
            wc_provider,
            registries,
            satellites,
            batch_interval,
            commitment_batch_window,
        }
    }

    pub fn add_satellite(&mut self, satellite: Arc<dyn Satellite>) {
        self.satellites.push(satellite);
    }

    async fn subscribe_registry_changes(
        &self,
    ) -> Result<futures::stream::SelectAll<BoxStream<'_, Result<RegistryChange>>>> {
        let p = &self.wc_provider;
        let r = &self.registries;

        Ok(futures::stream::select_all(vec![
            Box::pin(
                stream::watch_issuer_changes(p, r.issuer_registry)
                    .await?
                    .map(|r| r.map(RegistryChange::Issuer)),
            ) as BoxStream<'_, _>,
            Box::pin(
                stream::watch_oprf_key_changes(p, r.oprf_registry)
                    .await?
                    .map(|r| r.map(RegistryChange::OprfKey)),
            ),
            Box::pin(
                stream::watch_rp_registrations(p, r.rp_registry)
                    .await?
                    .map(|r| r.map(RegistryChange::RpRegistration)),
            ),
        ]))
    }

    /// Runs the relay engine loop. Never returns under normal operation.
    ///
    /// The relay pipeline:
    /// ```text
    /// ChainCommitted stream
    ///     → filter errors
    ///     → chunks_timeout(batch_window)   // accumulate sequential commits
    ///     → merge_commitments              // concat Commitment[] payloads
    ///     → flat_map(N satellites)          // fan out to each destination
    ///     → buffer_unordered               // build proofs + relay concurrently
    /// ```
    pub async fn run(&self) -> Result<()> {
        let mut registry_changes = self.subscribe_registry_changes().await?;

        // ── Relay pipeline ───────────────────────────────────────────────
        let satellites = self.satellites.clone();
        let concurrency = satellites.len().max(1);

        // Stage 1: raw commitment stream, filter decode errors.
        let committed = stream::watch_chain_committed(&self.wc_provider, self.registries.source)
            .await?
            .filter_map(|r| async {
                match r {
                    Ok(c) => Some(c),
                    Err(e) => {
                        error!(error = %e, "chain committed stream error");
                        None
                    }
                }
            });

        // Stage 2: batch sequential commitments over a time window.
        // Uses tokio_stream's chunks_timeout (UFCS to avoid trait conflict
        // with futures_util::StreamExt).
        let batched = tokio_stream::StreamExt::chunks_timeout(
            Box::pin(committed),
            MAX_COMMITMENT_BATCH,
            self.commitment_batch_window,
        );

        // Stage 3: merge each batch → fan out to satellites → buffer.
        let mut relays = Box::pin(
            batched
                .filter_map(|batch| async move {
                    let n = batch.len();
                    match merge_commitments(batch) {
                        Ok(merged) => {
                            info!(
                                merged = n,
                                chain_head = %merged.chain_head,
                                block = merged.block_number,
                                "commitment batch merged"
                            );
                            Some(Arc::new(merged))
                        }
                        Err(e) => {
                            error!(error = %e, "failed to merge commitment batch");
                            None
                        }
                    }
                })
                .flat_map(move |commitment| {
                    let sats = satellites.clone();
                    futures::stream::iter(sats.into_iter().map(move |sat| {
                        let commitment = Arc::clone(&commitment);
                        async move {
                            let name = sat.name().to_owned();
                            (name, sat.relay(&commitment).await)
                        }
                    }))
                })
                .buffer_unordered(concurrency),
        );

        // ── Engine state ─────────────────────────────────────────────────
        let mut pending = PendingChanges::default();
        let mut batch_ticker = tokio::time::interval(self.batch_interval);

        info!(
            source = %self.registries.source,
            satellite_count = self.satellites.len(),
            batch_interval = ?self.batch_interval,
            commitment_batch_window = ?self.commitment_batch_window,
            "relay engine started"
        );

        // ── Main loop ────────────────────────────────────────────────────
        loop {
            tokio::select! {
                Some(result) = registry_changes.next() => {
                    match result {
                        Ok(change) => {
                            info!(?change, "registry change detected");
                            pending.apply(change);
                        }
                        Err(e) => warn!(error = %e, "registry stream error"),
                    }
                }

                _ = batch_ticker.tick() => {
                    if pending.is_empty() {
                        continue;
                    }

                    let (issuers, oprfs) = pending.drain_ids();
                    info!(issuers = issuers.len(), oprfs = oprfs.len(), "propagating");

                    match propagate::propagate_state(
                        &self.wc_provider,
                        self.registries.source,
                        &issuers,
                        &oprfs,
                    )
                    .await
                    {
                        Ok(Some(tx)) => info!(%tx, "propagation succeeded"),
                        Ok(None) => info!("propagation: nothing changed on-chain"),
                        Err(e) => {
                            error!(error = %e, "propagation failed, re-queuing");
                            pending.issuer_schema_ids.extend(issuers);
                            pending.oprf_key_ids.extend(oprfs);
                        }
                    }
                }

                Some((name, outcome)) = relays.next() => {
                    match outcome {
                        Ok(tx) => info!(satellite = %name, %tx, "relay successful"),
                        Err(e) => error!(satellite = %name, error = %e, "relay failed"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_changes_empty_by_default() {
        let changes = PendingChanges::default();
        assert!(changes.is_empty());
    }

    #[test]
    fn pending_changes_apply_and_drain() {
        let mut changes = PendingChanges::default();
        changes.apply(RegistryChange::Issuer(1));
        changes.apply(RegistryChange::Issuer(1));
        changes.apply(RegistryChange::OprfKey(2));
        changes.apply(RegistryChange::RpRegistration(3));

        assert!(!changes.is_empty());
        assert_eq!(changes.issuer_schema_ids.len(), 1);
        assert_eq!(changes.oprf_key_ids.len(), 2);

        let (issuers, oprfs) = changes.drain_ids();
        assert_eq!(issuers, vec![1]);
        assert!(oprfs.contains(&2));
        assert!(oprfs.contains(&3));
        assert!(changes.is_empty());
    }

    #[test]
    fn pending_changes_clear() {
        let mut changes = PendingChanges::default();
        changes.apply(RegistryChange::Issuer(10));
        changes.apply(RegistryChange::OprfKey(20));
        changes.clear();
        assert!(changes.is_empty());
    }
}
