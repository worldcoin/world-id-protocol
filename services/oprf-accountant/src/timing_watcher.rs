//! Keeps a live, in-memory copy of the `BillingContract`'s [`TimingEra`] history.
//!
//! [`TimingWatcher::init`] fetches the full era history once over HTTP, then subscribes to
//! `TimingUpdated` events over a websocket connection to append new eras as they're appended
//! on-chain, so callers always have an up-to-date [`TimingEras`] snapshot without repolling.

use std::sync::{Arc, Mutex};

use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    pubsub::{ConnectionHandle, PubSubConnect},
    transports::{TransportError, TransportErrorKind, TransportResult},
};
use eyre::Context as _;
use futures_util::StreamExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use tokio_util::sync::CancellationToken;

use crate::accountant_service::{
    IBillingContract::{IBillingContractInstance, TimingUpdated},
    TimingEra,
};

/// Shared, mutex-guarded snapshot of the `BillingContract`'s timing-era history (oldest first),
/// kept live by [`TimingWatcher`].
pub(crate) type TimingEras = Arc<Mutex<Vec<TimingEra>>>;

/// Spawns a background task that keeps a [`TimingEras`] snapshot in sync with the
/// `BillingContract`'s `TimingUpdated` events.
///
/// [`TimingWatcher`] itself holds no state: [`TimingWatcher::init`] returns the shared
/// [`TimingEras`] handle that the spawned task updates in place.
#[derive(Clone)]
pub(crate) struct TimingWatcher;

impl TimingWatcher {
    /// Fetches the current era history via `http_provider`, then spawns a background task that
    /// appends new eras as `TimingUpdated` events arrive over a websocket at `ws_rpc_url`.
    ///
    /// The returned [`TimingEras`] is updated in place by the spawned task, so callers should
    /// keep using the same handle to see live updates. The task keeps running until
    /// `cancellation_token` is cancelled or the event stream ends (e.g. after a persistent
    /// websocket failure); on stream end it logs a warning and stops, after which the returned
    /// snapshot goes stale.
    ///
    /// If the websocket connection drops, [`TimingWatcherWsConnect::try_reconnect`] re-fetches
    /// the full era history on reconnect, so eras appended while disconnected aren't missed.
    ///
    /// # Errors
    /// Returns an error if the initial `getEras` call over `http_provider` fails, if connecting
    /// the websocket provider fails, or if subscribing to `TimingUpdated` fails.
    pub(crate) async fn init(
        contract_address: Address,
        http_provider: DynProvider,
        ws_rpc_url: SecretString,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<TimingEras> {
        let http_contract = IBillingContractInstance::new(contract_address, http_provider);
        let timing_eras = Arc::new(Mutex::new(Vec::new()));

        let ws_rpc_provider = ProviderBuilder::new()
            .connect_pubsub_with(TimingWatcherWsConnect {
                ws_connect: WsConnect::new(ws_rpc_url.expose_secret()),
                contract: http_contract.clone(),
                timing_eras: Arc::clone(&timing_eras),
            })
            .await
            .context("while connecting ws provider")?
            .erased();

        let contract = IBillingContractInstance::new(contract_address, ws_rpc_provider);
        let sub = contract.TimingUpdated_filter().subscribe().await?;
        let mut events = sub.into_stream();

        // Fetches the initial era history after we subscribe, so we don't miss any eras that were appended between the initial fetch and the subscription.
        *timing_eras.lock().expect("not poisoned") = http_contract
            .getEras()
            .call()
            .await
            .context("while fetching initial timing eras")?;

        // Appends each decoded `TimingUpdated` event to `timing_eras` as it arrives, until
        // cancelled or the event stream ends.
        tokio::spawn({
            let timing_eras = timing_eras.clone();
            async move {
                let _guard = cancellation_token.drop_guard_ref();

                loop {
                    tokio::select! {
                        event = events.next() => {
                            let Some(event) = event else {
                                tracing::warn!(
                                    "TimingUpdated event stream ended; new eras will no longer be picked up live"
                                );
                                break;
                            };

                            match event {
                                Ok((
                                    TimingUpdated {
                                        epochLength,
                                        votingWindow,
                                        paymentWindow,
                                        eraStartEpoch,
                                        eraStartTime,
                                    },
                                    _log,
                                )) => {
                                    let era = TimingEra {
                                        startEpoch: eraStartEpoch,
                                        startTime: eraStartTime,
                                        epochLength,
                                        votingWindow,
                                        paymentWindow,
                                    };
                                    tracing::trace!(?era, "received TimingUpdated event; appending to timing eras");
                                    let mut timing_eras = timing_eras.lock().expect("not poisoned");
                                    // we could get a event for a new TimingEra that we already have in our list if the event happened right after we fetch them initially or when we fetch them all in try_reconnect.
                                    if timing_eras.last().is_some_and(|last| last.startEpoch >= era.startEpoch) {
                                        tracing::warn!(
                                            "received TimingUpdated event with non-increasing startEpoch; skipping"
                                        );
                                    } else {
                                        timing_eras.push(era);
                                    }

                                }
                                Err(err) => {
                                    tracing::warn!(error = ?err, "failed to decode TimingUpdated event; skipping");
                                }
                            }
                        }
                        () = cancellation_token.cancelled() => {
                            tracing::info!("shutdown signal received, stopping TimingUpdated watcher");
                            break;
                        }
                    }
                }
            }
        });

        Ok(timing_eras)
    }
}

/// [`PubSubConnect`] wrapper that resyncs the full timing-era history from `contract` whenever
/// the websocket connection is (re)established, so eras appended on-chain while the connection
/// was down aren't silently missed.
pub(crate) struct TimingWatcherWsConnect {
    ws_connect: WsConnect,
    contract: IBillingContractInstance<DynProvider>,
    timing_eras: Arc<Mutex<Vec<TimingEra>>>,
}

impl PubSubConnect for TimingWatcherWsConnect {
    fn is_local(&self) -> bool {
        self.ws_connect.is_local()
    }

    async fn connect(&self) -> TransportResult<ConnectionHandle> {
        self.ws_connect.connect().await
    }

    async fn try_reconnect(&self) -> TransportResult<ConnectionHandle> {
        let handle = self.ws_connect.connect().await?;
        let eras = self
            .contract
            .getEras()
            .call()
            .await
            .map_err(|e| TransportError::Transport(TransportErrorKind::Custom(e.into())))?;
        *self.timing_eras.lock().expect("not poisoned") = eras;
        Ok(handle)
    }
}
