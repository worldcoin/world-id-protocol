//! Background resolution of committed wallet transactions.
//!
//! Each pass probes every wallet record and settles what the chain has
//! decided: confirmed or reverted, replaced, never landed, or still unknown
//! past the resolution timeout (parked). Every write is guarded, so replicas
//! resolving the same wallet cannot clobber each other.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use alloy::{primitives::Address, providers::DynProvider};
use futures::StreamExt as _;
use rand::Rng as _;
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};

use super::{RESOLVER_CONCURRENCY, TransactionSubmitter, probe, probe::Probe};
use crate::{
    metrics,
    request_tracker::{now_unix_secs, receipt_status},
    storage::{
        request_store::{StatusGuard, StatusWriteOutcome},
        wallet_store::{CasOutcome, Submission, WalletRecord, WalletState},
    },
};

/// Lower bound on how long one resolution pass may take before it is
/// abandoned, so a Redis or RPC call that accepts a connection and never
/// answers cannot wedge the loop.
const MIN_PASS_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound on the pause between passes while the RPC keeps failing.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// How a resolved batch ended, for the outcome metric and the nonce floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resolution {
    Confirmed,
    Reverted,
    /// A parked wallet's transaction landed after its requests were reported
    /// failed.
    ParkedLanded,
    Replaced,
    Absent,
}

impl Resolution {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Reverted => "reverted",
            Self::ParkedLanded => "parked_landed",
            Self::Replaced => "replaced",
            Self::Absent => "absent",
        }
    }

    /// Whether the wallet's nonce was used up, by this transaction or another.
    const fn consumes_nonce(self) -> bool {
        !matches!(self, Self::Absent)
    }
}

impl TransactionSubmitter {
    /// Runs the resolution loop until the process exits.
    ///
    /// Errors are handled per wallet and per pass, so the loop never returns
    /// one. Passes are spaced by the resolver interval with ±20% jitter, so
    /// replicas started together do not probe in lockstep. While passes keep
    /// hitting RPC failures the spacing doubles, up to [`MAX_BACKOFF`], so a
    /// degraded provider is not hammered by every replica.
    pub(crate) async fn run_resolver(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.resolver_interval_secs);
        let pass_timeout = interval.max(MIN_PASS_TIMEOUT);
        let mut failing_passes = 0u32;

        loop {
            let healthy = match tokio::time::timeout(pass_timeout, self.resolve_all()).await {
                Ok(healthy) => healthy,
                Err(_) => {
                    metrics::increment_wallet_error("resolve", "timeout");
                    tracing::error!(
                        timeout_secs = pass_timeout.as_secs(),
                        "resolution pass did not finish in time; abandoning it"
                    );
                    false
                }
            };
            failing_passes = if healthy {
                0
            } else {
                failing_passes.saturating_add(1)
            };

            let base = interval
                .saturating_mul(2u32.saturating_pow(failing_passes.min(16)))
                .min(MAX_BACKOFF.max(interval));
            let pause = base.mul_f64(rand::thread_rng().gen_range(0.8..1.2));
            tokio::time::sleep(pause).await;
        }
    }

    /// One resolution pass over every wallet that has a record.
    ///
    /// That is the configured wallets plus any other record in Redis: a pool
    /// key removed without draining, or the per-replica key of a replica that
    /// was scaled down, still has a transaction someone must decide. Resolving
    /// needs only the address, never the signer.
    ///
    /// Returns whether the pass was healthy, i.e. no probe found the RPC
    /// unavailable and the records could be read.
    pub(crate) async fn resolve_all(&self) -> bool {
        let mut addresses: Vec<Address> = self.wallets.iter().map(|entry| entry.address).collect();
        match self.wallet_store.addresses().await {
            Ok(stored) => {
                let unconfigured: Vec<Address> = stored
                    .into_iter()
                    .filter(|address| !addresses.contains(address))
                    .collect();
                metrics::record_wallet_unconfigured(unconfigured.len());
                addresses.extend(unconfigured);
            }
            Err(error) => {
                // The configured wallets can still be resolved without the index.
                metrics::increment_wallet_error("resolve", "redis");
                tracing::warn!(%error, "failed to list wallet records; resolving configured wallets only");
            }
        }

        let records = match self.wallet_store.get_many(&addresses).await {
            Ok(records) => records,
            Err(error) => {
                metrics::increment_wallet_error("resolve", "redis");
                tracing::error!(%error, "failed to load wallet records");
                return false;
            }
        };

        let in_flight = records
            .iter()
            .flatten()
            .filter(|record| record.state == WalletState::InFlight)
            .count();
        let parked = records
            .iter()
            .flatten()
            .filter(|record| record.state == WalletState::Parked)
            .count();
        metrics::record_wallet_pool_state(in_flight, parked);

        let active: Vec<(Address, WalletRecord)> = addresses
            .into_iter()
            .zip(records)
            .filter_map(|(address, record)| record.map(|record| (address, record)))
            .filter(|(_, record)| record.state != WalletState::Signing)
            .collect();

        // One provider for the whole pass, so every read it makes is answered by
        // the same node.
        let pass = self.resolver_pass.fetch_add(1, Ordering::Relaxed);
        let provider = self.resolver_providers[pass % self.resolver_providers.len()].clone();
        // Shorter than the shortest jittered spacing (0.8x), so a replica's own
        // next pass is never blocked by its previous claim, while replicas
        // together still probe each wallet about once per interval.
        let claim = Duration::from_secs(self.config.resolver_interval_secs).mul_f64(0.75);

        let outcomes: Vec<bool> = futures::stream::iter(active)
            .map(|(wallet, record)| {
                let provider = provider.clone();
                async move {
                    match self.wallet_store.claim_resolution(wallet, claim).await {
                        Ok(true) => self.resolve_wallet(wallet, &record, &provider).await,
                        // Another replica resolves this wallet in this interval.
                        Ok(false) => true,
                        Err(error) => {
                            metrics::increment_wallet_error("resolve", "redis");
                            tracing::warn!(%error, %wallet, "failed to claim a wallet for resolution");
                            true
                        }
                    }
                }
            })
            .buffer_unordered(RESOLVER_CONCURRENCY)
            .collect()
            .await;
        outcomes.into_iter().all(|healthy| healthy)
    }

    /// Resolves one committed wallet record (`InFlight` or `Parked`), returning
    /// `false` when the RPC was unavailable.
    async fn resolve_wallet(
        &self,
        wallet: Address,
        record: &WalletRecord,
        provider: &DynProvider,
    ) -> bool {
        let lease_id = record.lease_id;

        let Some(submission) = record.submission() else {
            metrics::increment_wallet_error("resolve", "invalid_record");
            tracing::error!(
                %wallet,
                "wallet record has no signed transaction; it cannot be resolved automatically"
            );
            return true;
        };

        // Keep the record alive while we are still deciding its fate.
        if let Err(error) = self
            .wallet_store
            .touch(wallet, lease_id, self.state_ttl())
            .await
        {
            metrics::increment_wallet_error("resolve", "redis");
            tracing::warn!(%error, %wallet, "failed to refresh wallet record lifetime");
        }

        let age = now_unix_secs().saturating_sub(submission.submitted_at);
        let parked = record.state == WalletState::Parked;
        // Within the grace a submitter may still be inside its commit, guard and
        // broadcast sequence. Adopting its requests there would flip them out
        // from under the guard that authorises the broadcast, and concluding
        // `Absent` would fail a transaction that is still on its way. Inclusion
        // and replacement are evidence either way, so probing starts at once.
        let submitter_done = age >= self.config.absent_grace_secs;

        // A batch still in `Batching` after the grace was left behind by a
        // process that died between committing the record and writing the
        // statuses.
        if !parked && submitter_done {
            self.adopt_requests(wallet, submission).await;
        }

        let mut available = true;
        match probe::probe(
            provider,
            wallet,
            submission,
            self.config.release_confirmations,
            submission.submitted_at + self.config.absent_grace_secs,
        )
        .await
        {
            Probe::Wait => {}
            Probe::Unavailable => available = false,
            Probe::Included {
                success,
                confirmations,
            } => {
                self.settle(wallet, record, submission, success, confirmations)
                    .await;
                // Resolved: the record is released or retried on its own terms.
                // Falling through to the timeout check below would park a wallet
                // whose transaction is already accounted for.
                return true;
            }
            Probe::Replaced => {
                self.fail_replaced(wallet, record, submission).await;
                return true;
            }
            Probe::Absent if submitter_done => {
                self.fail_absent(wallet, record, submission).await;
                // Resolved: the transaction never landed, so its wallet is free.
                return true;
            }
            // Possibly still being broadcast; decide on a later pass.
            Probe::Absent => {}
        }

        if !parked && age >= self.config.resolution_timeout_secs {
            self.park(wallet, record, submission).await;
        }
        available
    }

    /// Marks a batch's requests as submitted so the resolver owns them.
    ///
    /// Guarded on `Batching`, so this is a no-op once the submitter has already
    /// written the status and cannot disturb a request another owner resolved.
    async fn adopt_requests(&self, wallet: Address, submission: &Submission) {
        let status = GatewayRequestState::Submitted {
            tx_hash: format!("{:#x}", submission.tx_hash),
        };
        match self
            .tracker
            .set_status_batch_if(
                &submission.request_ids,
                &[StatusGuard::Batching],
                status,
                Some(wallet),
            )
            .await
        {
            // Refused or missing: already adopted, or resolved by another owner.
            Ok(_) => {}
            Err(error) => {
                metrics::increment_wallet_error("resolve", "redis");
                tracing::warn!(%error, %wallet, "failed to adopt requests for an outstanding transaction");
            }
        }
    }

    /// Resolves a batch whose transaction is on chain, and releases the wallet.
    async fn settle(
        &self,
        wallet: Address,
        record: &WalletRecord,
        submission: &Submission,
        success: bool,
        confirmations: u64,
    ) {
        let tx_hash = format!("{:#x}", submission.tx_hash);
        let parked = record.state == WalletState::Parked;
        if parked {
            // The requests were already failed when the wallet was parked, and a
            // terminal answer is not taken back. Make the contradiction loud.
            tracing::error!(
                %tx_hash,
                %wallet,
                success,
                "a parked wallet's transaction landed after its requests were reported failed"
            );
        }
        if !success {
            tracing::error!(
                %tx_hash,
                %wallet,
                batch_type = %submission.batch_type,
                "batch transaction reverted on-chain"
            );
        }
        let resolution = match (parked, success) {
            (true, _) => Resolution::ParkedLanded,
            (false, true) => Resolution::Confirmed,
            (false, false) => Resolution::Reverted,
        };
        let status = receipt_status(success, &tx_hash);

        if self
            .resolve_batch(wallet, record, submission, &status, resolution)
            .await
        {
            let latency_ms = now_unix_secs()
                .saturating_sub(submission.submitted_at)
                .saturating_mul(1_000) as f64;
            metrics::record_batch_confirmed(submission.batch_type.as_str(), success, latency_ms);
            metrics::record_wallet_time_in_flight(latency_ms);
            metrics::record_wallet_confirmations_at_release(confirmations);
        }
    }

    /// Fails a batch whose nonce was consumed by a different transaction.
    async fn fail_replaced(&self, wallet: Address, record: &WalletRecord, submission: &Submission) {
        tracing::error!(
            %wallet,
            tx_hash = %format!("{:#x}", submission.tx_hash),
            nonce = submission.nonce,
            "wallet transaction was replaced; its requests cannot be confirmed"
        );
        let status = GatewayRequestState::failed(
            format!(
                "transaction replaced by another transaction with the same nonce (nonce {})",
                submission.nonce
            ),
            Some(GatewayErrorCode::ConfirmationError),
        );
        self.resolve_batch(wallet, record, submission, &status, Resolution::Replaced)
            .await;
    }

    /// Parks a wallet whose transaction fate could not be decided.
    ///
    /// The requests are failed so clients get a bounded answer, but the lease is
    /// deliberately kept: releasing the wallet could reuse a nonce whose
    /// transaction still exists. Parking is a capacity loss, not a correctness
    /// risk, and it stops the wallet until the chain settles or an operator acts.
    async fn park(&self, wallet: Address, record: &WalletRecord, submission: &Submission) {
        let status = GatewayRequestState::failed(
            format!(
                "transaction fate undecided after {}s (tx: {:#x})",
                self.config.resolution_timeout_secs, submission.tx_hash
            ),
            Some(GatewayErrorCode::ConfirmationError),
        );

        if !self
            .mark_terminal(&submission.request_ids, &status, wallet)
            .await
        {
            // Do not park on a failed write: the wallet would be out of the pool
            // with its requests still non-terminal, and nothing would retry the
            // write. Leaving the record in flight lets the next pass retry.
            tracing::warn!(
                %wallet,
                "could not resolve the batch's requests; leaving the wallet in flight to retry"
            );
            return;
        }

        let next = WalletRecord::parked(record.lease_id, submission.clone());
        match self
            .wallet_store
            .replace(
                wallet,
                record.lease_id,
                WalletState::InFlight,
                // The lease and state guards already ensure this is the record we
                // decided about.
                &next,
                self.state_ttl(),
            )
            .await
        {
            Ok(CasOutcome::Applied) => {
                metrics::record_wallet_outcome("parked");
                tracing::error!(
                    %wallet,
                    tx_hash = %format!("{:#x}", submission.tx_hash),
                    nonce = submission.nonce,
                    "wallet parked: transaction fate could not be decided; it will not be reused until resolved"
                );
            }
            Ok(outcome) => {
                tracing::warn!(%wallet, ?outcome, "wallet record changed before it could be parked");
            }
            Err(error) => {
                tracing::error!(%error, %wallet, "failed to park wallet");
            }
        }
    }

    /// Fails a batch whose transaction is neither on chain nor pending.
    ///
    /// [`Probe::Absent`] established that the nonce is unconsumed and the signed
    /// hash is unknown to the endpoint after the broadcast grace, so the
    /// transaction never landed and the wallet's nonce is free to reuse.
    /// Nothing is retried: the requests are answered and the wallet returns to
    /// the pool.
    async fn fail_absent(&self, wallet: Address, record: &WalletRecord, submission: &Submission) {
        let status = GatewayRequestState::failed(
            format!(
                "transaction was not accepted by the network (tx: {:#x})",
                submission.tx_hash
            ),
            Some(GatewayErrorCode::ConfirmationError),
        );
        self.resolve_batch(wallet, record, submission, &status, Resolution::Absent)
            .await;
    }

    /// Writes a batch's terminal status and releases its wallet.
    ///
    /// Returns whether this caller released the wallet. Two replicas can still
    /// resolve the same wallet when a resolution claim lapses mid-pass, so only
    /// the one whose release applied records the outcome.
    async fn resolve_batch(
        &self,
        wallet: Address,
        record: &WalletRecord,
        submission: &Submission,
        status: &GatewayRequestState,
        resolution: Resolution,
    ) -> bool {
        if !self
            .mark_terminal(&submission.request_ids, status, wallet)
            .await
        {
            return false;
        }
        // Recorded before the release, so the next holder of the wallet sees it.
        // Without it the wallet stays held and the next pass, which re-probes
        // the same outcome, retries: releasing would let a lagging node hand
        // the consumed nonce to the next batch.
        if resolution.consumes_nonce()
            && let Err(error) = self
                .wallet_store
                .raise_nonce_floor(wallet, submission.nonce + 1, self.state_ttl())
                .await
        {
            metrics::increment_wallet_error("release", "redis");
            tracing::warn!(%error, %wallet, "failed to record the nonce floor; keeping the wallet for the next pass");
            return false;
        }
        let released = self.release_lease(wallet, record.lease_id).await;
        if released {
            metrics::record_wallet_outcome(resolution.as_str());
        }
        released
    }

    /// Writes a terminal status for a batch, returning whether the wallet may be
    /// released.
    ///
    /// The batch write is all-or-nothing, so it refuses the whole batch when any
    /// request was already resolved by another owner or has expired. The
    /// remaining requests are then resolved one by one: leaving them for the
    /// next pass would refuse again forever, and the sweeper does not touch
    /// requests a wallet owns. The wallet is released only once every write has
    /// reached Redis.
    async fn mark_terminal(
        &self,
        ids: &[String],
        status: &GatewayRequestState,
        wallet: Address,
    ) -> bool {
        let allowed = [StatusGuard::Batching, StatusGuard::Submitted];
        match self
            .tracker
            .set_status_batch_if(ids, &allowed, status.clone(), Some(wallet))
            .await
        {
            Ok(StatusWriteOutcome::Applied) => true,
            Ok(StatusWriteOutcome::Guarded | StatusWriteOutcome::Missing) => {
                self.set_each_if(ids, &allowed, status, Some(wallet)).await
            }
            Err(error) => {
                metrics::increment_wallet_error("resolve", "redis");
                tracing::error!(%error, %wallet, "failed to write terminal status for a batch");
                false
            }
        }
    }
}
