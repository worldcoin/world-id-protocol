//! Aggregates recorded RP (relying party) OPRF request counts per epoch and submits them as
//! billing votes to the `BillingContract`.
//!
//! [`OprfAccountantService::run`] drives this on a timer: each
//! [`OprfAccountantService::tick`] checks whether the most recently closed epoch's voting
//! window is open (see [`get_votes_for_current_vote_window`]), and if so, aggregates that
//! epoch's recorded [`BillableRpRequest`]s by RP id (via [`PostgresDb`]) and submits the
//! resulting counts as this node's vote. The epoch cursor persisted in [`PostgresDb`] tracks
//! progress so a restart resumes from where it left off instead of re-voting for
//! already-processed epochs.
//!
//! `timing_eras` is seeded once from `getEras()` when the service is constructed (passed to
//! [`OprfAccountantService::new`]), then kept up to date by [`OprfAccountantService::tick`],
//! which re-fetches `getEras()` on every tick and refreshes the shared `Arc<Mutex<..>>` if it
//! changed. Since a tick runs at least once per voting window, no `TimingUpdated` change is
//! ever missed.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::{primitives::Address, providers::DynProvider, signers::local::PrivateKeySigner, sol};
use eyre::Context;
use itertools::Itertools as _;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    accountant_service::IBillingContract::IBillingContractInstance, api::BillableRpRequest,
    postgres::PostgresDb,
};

// TODO replace with abi
sol! {
    #[derive(Debug, Copy, PartialEq, Eq)]
    struct TimingEra {
        // the first epoch governed by this era's parameters.
        uint32 startEpoch;
        // the timestamp the era starts at: the end of epoch `startEpoch - 1` (genesis for era 0).
        uint64 startTime;
        // the epoch length in seconds.
        uint64 epochLength;
        // the voting window in seconds (<= epochLength).
        uint64 votingWindow;
        // the payment window in seconds.
        uint64 paymentWindow;
    }

    /// @notice A single (rpId, count) entry inside a node's billing vote.
    #[derive(Debug, PartialEq, Eq)]
    struct RpCount {
        // the Relying Party the count is reported for.
        uint64 rpId;
        // the number of unique requests the node observed for the RP in the epoch.
        uint64 count;
    }

    /// @notice One chunk of an OPRF node's signed billing vote for a single epoch.
    /// @dev The signed payload is the EIP-712
    ///      `BillingVoteChunk(uint32 epoch,uint32 chunkIndex,bool isFinal,RpCount[] counts)` struct,
    ///      where `epoch` is supplied as the call argument shared by every chunk in the batch.
    struct SignedVoteChunk {
        // the zero-based chunk index for this node and epoch. Chunks must be submitted in order.
        uint32 chunkIndex;
        // true on the final chunk; the node counts as a voter only after this chunk is accepted.
        bool isFinal;
        // the per-RP counts reported by the node, strictly ascending globally across chunks,
        // all counts non-zero.
        RpCount[] counts;
        // the node's EIP-712 signature over the chunk. The signer is recovered, not trusted from
        // msg.sender, so any party may relay the chunks.
        bytes signature;
    }

    #[sol(rpc)]
    interface IBillingContract {
        // Emitted when the epoch timing parameters are updated.
        event TimingUpdated(
            uint64 epochLength, uint64 votingWindow, uint64 paymentWindow, uint32 eraStartEpoch, uint64 eraStartTime
        );

         // The full timing-era history, oldest first; the last entry is the current era.
        function getEras() external view returns (TimingEra[] memory);

         // Submit one or more OPRF node billing vote chunks for a single epoch.
         //
         // Records votes only; does not finalize as a side effect (finalization is driven solely by
         // {finalizeEpochs}), so a node's vote gas never carries another epoch's finalization cost.
         // Quorum and pricing are read live at finalization (no per-epoch snapshot). Authenticates
         // by recovered signer, not msg.sender. A node's chunks must be submitted in order and the
         // node counts toward quorum only after its final chunk is accepted.
        function submitBillingVotes(uint32 epoch, SignedVoteChunk[] calldata chunks) external;
    }
}

sol! {
    /// EIP-712 typed-data payload for a single [`SignedVoteChunk`] (without its `signature`
    /// field, which is what's being computed). Used only for signature hashing/recovery, not
    /// as a Solidity call type.
    struct BillingVoteChunk {
        uint32 epoch;
        uint32 chunkIndex;
        bool isFinal;
        RpCount[] counts;
    }
}

/// Outcome of checking whether we can vote right now for the most recently closed epoch.
#[derive(Debug, PartialEq)]
enum VoteWindowResult {
    /// The most recently closed epoch's voting window either hasn't opened yet, or it opened
    /// but `voting_window_offset` hasn't elapsed yet (giving OPRF nodes time to flush their
    /// batched requests to us before we aggregate).
    NotOpen,
    /// The most recently closed epoch's voting window has already closed; we can no longer
    /// vote for it.
    AlreadyClosed,
    /// The most recently closed epoch's voting window is open now.
    Vote {
        // the epoch to vote for (the last fully closed epoch).
        epoch: u32,
        // the per-RP counts for the epoch, ascending by `rpId` (as required by `submitBillingVotes`).
        counts: Vec<RpCount>,
    },
}

/// Aggregates recorded RP request counts per epoch and submits them as billing votes.
///
/// Constructed via [`OprfAccountantService::new`]; driven by repeatedly calling
/// [`OprfAccountantService::tick`] (typically via [`OprfAccountantService::run`]).
#[derive(Clone)]
#[expect(
    dead_code,
    reason = "unused fields are used in the future implementation of vote submission"
)]
pub(crate) struct OprfAccountantService {
    contract: IBillingContractInstance<DynProvider>,
    billing_contract: Address,
    chain_id: u64,
    signer: PrivateKeySigner,
    db: PostgresDb,
    timing_eras: Arc<Mutex<Vec<TimingEra>>>,
    submit_interval: Duration,
    voting_window_offset: Duration,
    cancellation_token: CancellationToken,
}

/// Construction parameters for [`OprfAccountantService::new`].
pub(crate) struct OprfAccountantServiceArgs {
    /// Provider used to call and sign transactions against the `BillingContract`.
    pub(crate) provider: DynProvider,
    /// Chain id `provider` is connected to.
    pub(crate) chain_id: u64,
    /// Address of the `BillingContract`.
    pub(crate) billing_contract: Address,
    /// Signer this node uses to sign its billing votes.
    pub(crate) signer: PrivateKeySigner,
    /// Database storing recorded RP requests and the epoch cursor.
    pub(crate) db: PostgresDb,
    /// Initial `TimingEra` history of the `BillingContract`.
    /// Must have at least one entry (the `BillingContract` adds its first `TimingEra` on initialization).
    pub(crate) timing_eras: Vec<TimingEra>,
    /// How often [`OprfAccountantService::run`] calls [`OprfAccountantService::tick`]. Must be
    /// less than the current era's `epochLength` and `votingWindow` (see [`validate_timing`]).
    pub(crate) submit_interval: Duration,
    /// Extra delay after an epoch's voting window opens before we aggregate and vote for it,
    /// giving OPRF nodes time to flush their batched requests to us. Must be less than the
    /// current era's `votingWindow` (see [`validate_timing`]).
    pub(crate) voting_window_offset: Duration,
    /// Signals [`OprfAccountantService::run`] to stop.
    pub(crate) cancellation_token: CancellationToken,
}

impl OprfAccountantService {
    /// Constructs the service: builds the `BillingContract` binding and validates
    /// `submit_interval`/`voting_window_offset` against the current timing era.
    ///
    /// # Errors
    /// Returns an error if the current era's timing parameters fail [`validate_timing`].
    ///
    /// # Panics
    /// Panics if `timing_eras` is empty.
    pub(crate) async fn new(
        OprfAccountantServiceArgs {
            provider,
            chain_id,
            billing_contract,
            signer,
            db,
            timing_eras,
            submit_interval,
            voting_window_offset,
            cancellation_token,
        }: OprfAccountantServiceArgs,
    ) -> eyre::Result<Self> {
        let contract = IBillingContract::new(billing_contract, provider);
        validate_timing(
            timing_eras.last().expect("at least one timing era"),
            submit_interval,
            voting_window_offset,
        )?;

        Ok(Self {
            contract,
            billing_contract,
            chain_id,
            signer,
            db,
            timing_eras: Arc::new(Mutex::new(timing_eras)),
            submit_interval,
            voting_window_offset,
            cancellation_token,
        })
    }

    /// Persists a batch of [`BillableRpRequest`]s, bucketed into the epoch each request's
    /// `expires_at` falls into.
    ///
    /// This reads `timing_eras` from the shared cache rather than fetching it fresh, so there's
    /// a brief window — up to one `submit_interval` — after a `TimingUpdated` event where a
    /// request landing right at the new era's boundary could be bucketed using the stale era.
    /// This is fine: the cache is refreshed at least once per voting window (see
    /// [`OprfAccountantService::tick`]), so it self-corrects on the very next tick, and
    /// `TimingUpdated` (an owner-only, operational change) is expected to be rare.
    ///
    /// # Errors
    /// Returns an error if the underlying database write fails.
    #[instrument(
        level = "trace",
        skip_all,
        name = "accountant_service::record_rp_request_batch"
    )]
    pub(crate) async fn record_rp_request_batch(
        &self,
        rp_requests: Vec<BillableRpRequest>,
    ) -> eyre::Result<()> {
        tracing::trace!(
            num_requests = rp_requests.len(),
            "recording RP request batch"
        );
        let epochs = {
            let timing_eras = self.timing_eras.lock().expect("not poisoned");
            rp_requests
                .iter()
                .map(|r| epoch_for_timestamp(&timing_eras, r.expires_at))
                .collect_vec()
        };
        self.db
            .store_request_batch(epochs, rp_requests)
            .await
            .context("while storing request batch")
    }

    /// Runs the service until `cancellation_token` is cancelled, calling [`Self::tick`] every
    /// `submit_interval`.
    ///
    /// A tick that returns an error is logged and retried on the next tick rather than stopping
    /// the loop, since a transient failure (e.g. a dropped DB connection) shouldn't prevent
    /// later epochs from being voted on.
    pub(crate) async fn run(&self) {
        tracing::info!("starting OprfAccountant worker");

        let mut interval = tokio::time::interval(self.submit_interval);
        // Burst would also be fine, but it is not needed here, Skip would be bad because it could skip epochs
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(err) = self.tick().await {
                        tracing::error!(error = ?err, "accountant tick failed; retrying next tick");
                    }
                }
                _ = self.cancellation_token.cancelled() => {
                    tracing::info!("shutdown signal received, stopping account worker");
                    break;
                }
            }
        }
    }

    /// Determines whether we can vote right now for the most recently closed epoch as of `now`
    /// (see [`VoteWindowResult`]), aggregating that epoch's recorded counts if so.
    ///
    /// # Errors
    /// Returns an error if the current era's timing parameters fail [`validate_timing`], or if
    /// fetching the epoch's request counts from the database fails.
    #[instrument(
        level = "trace",
        skip_all,
        name = "accountant_service::get_votes_for_current_vote_window"
    )]
    async fn get_votes_for_current_vote_window(&self, now: u64) -> eyre::Result<VoteWindowResult> {
        let eras = self.timing_eras.lock().expect("not poisoned").clone();
        validate_timing(
            eras.last().expect("at least one timing era"),
            self.submit_interval,
            self.voting_window_offset,
        )?;

        let current_epoch = epoch_for_timestamp(&eras, now);
        if current_epoch == 0 {
            // no epochs have closed yet, so we have nothing to vote for.
            return Ok(VoteWindowResult::NotOpen);
        }

        // the epoch we vote for is the last fully closed epoch (i.e. is strictly before the epoch `now` falls into).
        let epoch = current_epoch - 1;
        let (window_open, window_close) = voting_window(&eras, epoch);
        let submit_after = window_open + self.voting_window_offset.as_secs();

        if now < submit_after {
            // not enough time has passed since the epoch closed for OPRF nodes' batched
            // requests to have flushed to us yet; wait and pick this epoch back up next tick.
            tracing::trace!(
                epoch,
                window_open,
                window_close,
                submit_after,
                now,
                "voting window not open yet"
            );
            return Ok(VoteWindowResult::NotOpen);
        }

        if now >= window_close {
            tracing::warn!(
                epoch,
                window_open,
                window_close,
                submit_after,
                now,
                "voting window closed before we could vote for this epoch"
            );
            return Ok(VoteWindowResult::AlreadyClosed);
        }

        let counts = self.db.rp_counts_for_epoch(epoch).await?;
        Ok(VoteWindowResult::Vote { epoch, counts })
    }

    /// Submits `counts` as this node's billing vote for `epoch`. A no-op if `counts` is empty.
    ///
    /// # Errors
    /// Returns an error if submitting the vote fails.
    async fn vote_for_epoch(&self, _epoch: u32, counts: Vec<RpCount>) -> eyre::Result<()> {
        if counts.is_empty() {
            return Ok(());
        }

        // TODO

        Ok(())
    }

    /// One iteration of the accounting loop: refreshes the local timing-era cache from the
    /// contract (see the module docs), then checks whether the most recently closed epoch's
    /// voting window is open (see [`Self::get_votes_for_current_vote_window`]) and, if so and we
    /// haven't already voted for it, submits the vote and advances the epoch cursor.
    ///
    /// Logs a warning if the epoch cursor is more than one epoch behind the epoch we're about to
    /// vote for, meaning one or more epochs were skipped (e.g. after downtime longer than a
    /// voting window).
    ///
    /// # Errors
    /// Returns an error if fetching the timing eras, checking the vote window, submitting the
    /// vote, or updating the epoch cursor fails.
    #[instrument(level = "info", skip_all, name = "accountant_service::tick")]
    pub(crate) async fn tick(&self) -> eyre::Result<()> {
        let now = now_unix_timestamp();

        // Fetch the latest timing eras from the contract and update our local copy if it has changed.
        // This ensures that we always have the most up-to-date timing information for determining voting windows.
        // Current epoch is not affected by timing changes, new parameters affect later epochs only.
        // Ticks should happen at least once per `voting_window` (which is guaranteed to be at most `epochLength`),
        // so we should never miss a timing update.
        let timing_eras = self
            .contract
            .getEras()
            .call()
            .await
            .context("while fetching initial timing eras")?;
        {
            let mut current_timing_eras = self.timing_eras.lock().expect("not poisoned");
            if timing_eras != *current_timing_eras {
                tracing::info!(
                    ?timing_eras,
                    ?current_timing_eras,
                    "timing eras changed; updating"
                );
                *current_timing_eras = timing_eras;
            }
        }

        match self.get_votes_for_current_vote_window(now).await? {
            VoteWindowResult::NotOpen => {
                tracing::trace!("voting window not open yet");
            }
            VoteWindowResult::AlreadyClosed => {
                tracing::warn!("voting window already closed");
            }
            VoteWindowResult::Vote { epoch, counts } => {
                let epoch_cursor = self.db.get_epoch_cursor().await?;
                if (epoch as i64).abs_diff(epoch_cursor) > 1 {
                    tracing::warn!(
                        epoch,
                        epoch_cursor,
                        "epoch cursor is more than one behind; some epochs may have been skipped"
                    );
                }
                if epoch as i64 > epoch_cursor {
                    tracing::info!(epoch, ?counts, "submitting billing vote for epoch");
                    self.vote_for_epoch(epoch, counts).await?;
                    tracing::info!(epoch, "successfully submitted billing vote for epoch");
                    self.db.set_epoch_cursor(epoch).await?;
                } else {
                    tracing::trace!(epoch, epoch_cursor, "already voted for this epoch");
                }
            }
        }

        Ok(())
    }
}

/// Validates `tick_interval` and `voting_window_offset` against `era`'s timing parameters.
///
/// # Errors
/// Returns an error if `era.votingWindow` is not at most `era.epochLength` (consecutive epochs'
/// voting windows could overlap), if `voting_window_offset` is not less than `era.votingWindow`
/// (votes would never be submitted), or if `tick_interval` is not less than `era.votingWindow`
/// (a tick can walk straight past an epoch's voting window).
fn validate_timing(
    era: &TimingEra,
    tick_interval: Duration,
    voting_window_offset: Duration,
) -> eyre::Result<()> {
    eyre::ensure!(
        era.votingWindow <= era.epochLength,
        "era votingWindow ({}s) must be at most the epochLength ({}s), or voting windows for \
         consecutive epochs could overlap",
        era.votingWindow,
        era.epochLength
    );
    eyre::ensure!(
        voting_window_offset.as_secs() < era.votingWindow,
        "voting_window_offset ({voting_window_offset:?}) must be less than the current voting \
         window ({}s), or votes would never be submitted",
        era.votingWindow
    );
    eyre::ensure!(
        tick_interval.as_secs() < era.votingWindow,
        "tick_interval ({tick_interval:?}) must be less than the current voting window \
         ({}s), or a tick can walk straight past an epoch's voting window",
        era.votingWindow
    );
    Ok(())
}

/// Returns the era whose timespan `[startTime, nextEra.startTime)` contains `timestamp`: the
/// most recent era that had already started by `timestamp`, falling back to the oldest era for
/// timestamps that predate it.
///
/// # Panics
/// Panics if `eras` is empty.
fn era_for_timestamp(eras: &[TimingEra], timestamp: u64) -> &TimingEra {
    eras.iter()
        .rev()
        .find(|era| era.startTime <= timestamp)
        .or_else(|| eras.first())
        .expect("at least one timing era")
}

/// Returns the era governing `epoch`'s span: the era with the largest `startEpoch <= epoch`,
/// falling back to the oldest era for epochs older than any known era.
///
/// # Panics
/// Panics if `eras` is empty.
fn era_for_epoch(eras: &[TimingEra], epoch: u32) -> &TimingEra {
    eras.iter()
        .rev()
        .find(|era| era.startEpoch <= epoch)
        .or_else(|| eras.first())
        .expect("at least one timing era")
}

/// Returns the epoch a timestamp falls into, given the full timing-era history (oldest first,
/// as returned by [`IBillingContract::getEras`]): the epoch `e` such that
/// `epoch_start(e) <= timestamp < epoch_end(e)`, per the boundary formula documented on the
/// `BillingContract`'s `epochEnd` function.
///
/// # Panics
/// Panics if `eras` is empty.
pub(crate) fn epoch_for_timestamp(eras: &[TimingEra], timestamp: u64) -> u32 {
    let era = era_for_timestamp(eras, timestamp);
    let elapsed_epochs = timestamp.saturating_sub(era.startTime) / era.epochLength;
    era.startEpoch
        .saturating_add(u32::try_from(elapsed_epochs).unwrap_or(u32::MAX))
}

/// Returns the timestamp at which `epoch` ends (and, per the contract's window semantics, at
/// which its voting window opens), using the era governing `epoch`'s span.
fn epoch_end(eras: &[TimingEra], epoch: u32) -> u64 {
    let span_era = era_for_epoch(eras, epoch);
    let epochs_since_era_start = u64::from(epoch - span_era.startEpoch) + 1;
    span_era.startTime + epochs_since_era_start * span_era.epochLength
}

/// Returns the `[open, close)` voting window for `epoch`. The window opens when the epoch ends
/// and uses the `votingWindow` of whichever era governs at that instant — which, for the last
/// epoch before a timing change, can differ from the era governing the epoch's span.
fn voting_window(eras: &[TimingEra], epoch: u32) -> (u64, u64) {
    let open = epoch_end(eras, epoch);
    let era = era_for_timestamp(eras, open);
    (open, open + era.votingWindow)
}

/// Returns the current unix timestamp in seconds.
fn now_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU32, time::Duration};

    use alloy::{
        primitives::Address,
        providers::{Provider as _, ProviderBuilder},
        signers::local::PrivateKeySigner,
        transports::mock::Asserter,
    };
    use secrecy::SecretString;
    use taceo_nodes_common::{
        postgres::PostgresConfig,
        test_utils::{next_test_schema, shared_postgres_testcontainer},
    };
    use tokio_util::sync::CancellationToken;
    use world_id_primitives::rp::RpId;

    use super::{
        OprfAccountantService, RpCount, TimingEra, VoteWindowResult, epoch_end,
        epoch_for_timestamp, era_for_epoch, era_for_timestamp, voting_window,
    };
    use crate::{
        accountant_service::OprfAccountantServiceArgs, api::BillableRpRequest, postgres::PostgresDb,
    };

    /// The exact walkthrough from the `TimingEra` doc comment: era 0 =
    /// `{startEpoch: 0, startTime: 1000, len: 100, vote: 80, pay: 200}`, and `setTiming(50, 40,
    /// 100)` is called at t=1250 (inside epoch 2), appending era 1 = `{startEpoch: 3, startTime:
    /// 1300, len: 50, vote: 40, pay: 100}`.
    fn example_eras() -> Vec<TimingEra> {
        vec![
            TimingEra {
                startEpoch: 0,
                startTime: 1000,
                epochLength: 100,
                votingWindow: 80,
                paymentWindow: 200,
            },
            TimingEra {
                startEpoch: 3,
                startTime: 1300,
                epochLength: 50,
                votingWindow: 40,
                paymentWindow: 100,
            },
        ]
    }

    #[test]
    fn era_for_timestamp_returns_the_only_era_when_there_is_one() {
        let eras = vec![example_eras()[0]];
        assert_eq!(era_for_timestamp(&eras, 1000).startEpoch, 0);
        assert_eq!(era_for_timestamp(&eras, 50_000).startEpoch, 0);
    }

    #[test]
    fn era_for_timestamp_falls_back_to_the_oldest_era_before_it_started() {
        let eras = vec![example_eras()[0]];
        // 500 predates the only era's startTime (1000).
        assert_eq!(era_for_timestamp(&eras, 500).startEpoch, 0);
    }

    #[test]
    fn era_for_timestamp_picks_the_most_recently_started_era() {
        let eras = example_eras();
        // strictly inside era 0's span
        assert_eq!(era_for_timestamp(&eras, 1250).startEpoch, 0);
        // exactly at era 1's start: era 1 governs from here on
        assert_eq!(era_for_timestamp(&eras, 1300).startEpoch, 3);
        // strictly inside era 1's span
        assert_eq!(era_for_timestamp(&eras, 1350).startEpoch, 3);
    }

    #[test]
    fn era_for_epoch_returns_the_only_era_when_there_is_one() {
        let eras = vec![example_eras()[0]];
        assert_eq!(era_for_epoch(&eras, 0).startEpoch, 0);
        assert_eq!(era_for_epoch(&eras, 100).startEpoch, 0);
    }

    #[test]
    fn era_for_epoch_falls_back_to_the_oldest_era_for_epochs_older_than_any_known_era() {
        let old_era = TimingEra {
            startEpoch: 5,
            ..example_eras()[0]
        };
        let eras = vec![old_era];
        assert_eq!(era_for_epoch(&eras, 2).startEpoch, 5);
    }

    #[test]
    fn era_for_epoch_picks_the_era_with_the_largest_start_epoch_at_or_below_epoch() {
        let eras = example_eras();
        assert_eq!(era_for_epoch(&eras, 0).startEpoch, 0);
        assert_eq!(era_for_epoch(&eras, 2).startEpoch, 0);
        assert_eq!(era_for_epoch(&eras, 3).startEpoch, 3);
        assert_eq!(era_for_epoch(&eras, 10).startEpoch, 3);
    }

    #[test]
    fn epoch_for_timestamp_within_a_single_era() {
        let eras = vec![example_eras()[0]];
        // epoch 0 spans [1000, 1100)
        assert_eq!(epoch_for_timestamp(&eras, 1000), 0);
        assert_eq!(epoch_for_timestamp(&eras, 1050), 0);
        // epoch 1 spans [1100, 1200)
        assert_eq!(epoch_for_timestamp(&eras, 1100), 1);
        assert_eq!(epoch_for_timestamp(&eras, 1199), 1);
    }

    #[test]
    fn epoch_for_timestamp_matches_the_example_across_an_era_change() {
        let eras = example_eras();
        // t=1250: "inside epoch 2", per the doc comment, while era 0's parameters still apply
        // to the epoch's span even though era 1 has already been appended.
        assert_eq!(epoch_for_timestamp(&eras, 1250), 2);
        // epoch 3 spans [1300, 1350) under era 1's shorter length.
        assert_eq!(epoch_for_timestamp(&eras, 1300), 3);
        assert_eq!(epoch_for_timestamp(&eras, 1349), 3);
        // epoch 4 spans [1350, 1400).
        assert_eq!(epoch_for_timestamp(&eras, 1350), 4);
    }

    #[test]
    fn epoch_end_matches_the_example() {
        let eras = example_eras();
        // epoch 1 [1100, 1200) — era-0 span
        assert_eq!(epoch_end(&eras, 1), 1200);
        // epoch 2 [1200, 1300) — era-0 span (epoch 2 keeps era 0's length)
        assert_eq!(epoch_end(&eras, 2), 1300);
        // epoch 3 [1300, 1350) — era-1 span
        assert_eq!(epoch_end(&eras, 3), 1350);
    }

    #[test]
    fn voting_window_matches_the_example() {
        let eras = example_eras();

        // epoch 1: window [1200, 1280) — era-0 span, era-0 window.
        assert_eq!(voting_window(&eras, 1), (1200, 1280));
        // epoch 2: window [1300, 1340) — era-0 span, but era-1 window, since the window opens
        // exactly at the era boundary and is thus governed by the new era.
        assert_eq!(voting_window(&eras, 2), (1300, 1340));
        // epoch 3: window [1350, 1390) — era-1 span, era-1 window.
        assert_eq!(voting_window(&eras, 3), (1350, 1390));
    }

    /// Builds an [`OprfAccountantService`] backed by `eras`, a chain-less mock provider, and a
    /// fresh Postgres schema in the shared testcontainer.
    async fn setup_service(timing_eras: Vec<TimingEra>) -> OprfAccountantService {
        let connection_string = shared_postgres_testcontainer()
            .await
            .expect("shared postgres testcontainer starts");
        let mut db_config = PostgresConfig::with_default_values(
            SecretString::from(connection_string.to_owned()),
            next_test_schema(),
        );
        db_config.max_connections = NonZeroU32::new(1).expect("non-zero");
        let db = PostgresDb::init(&db_config)
            .await
            .expect("postgres db initializes");

        OprfAccountantService::new(OprfAccountantServiceArgs {
            provider: ProviderBuilder::new()
                .connect_mocked_client(Asserter::new())
                .erased(),
            chain_id: 31337,
            billing_contract: Address::ZERO,
            signer: PrivateKeySigner::random(),
            db,
            timing_eras,
            submit_interval: Duration::from_secs(1),
            voting_window_offset: Duration::from_secs(5),
            cancellation_token: CancellationToken::new(),
        })
        .await
        .expect("service constructs")
    }

    fn request(rp_id: u64, nonce: u64, expires_at: u64) -> BillableRpRequest {
        BillableRpRequest {
            rp_id: RpId::new(rp_id),
            nonce: ark_babyjubjub::Fq::from(nonce),
            created_at: expires_at,
            expires_at,
            action: ark_babyjubjub::Fq::from(0u64),
            signature: None,
        }
    }

    #[tokio::test]
    async fn not_ready_before_first_epoch_closes() {
        let service = setup_service(example_eras()).await;

        // still inside epoch 0's own span [1000, 1100); nothing has closed yet.
        let result = service
            .get_votes_for_current_vote_window(1050)
            .await
            .expect("computes vote window");

        assert_eq!(result, VoteWindowResult::NotOpen);
    }

    #[tokio::test]
    async fn not_ready_while_waiting_for_flush_offset() {
        let service = setup_service(example_eras()).await;

        // epoch 0's window opened at 1100, but submit_after (1105) hasn't passed yet.
        let result = service
            .get_votes_for_current_vote_window(1102)
            .await
            .expect("computes vote window");

        assert_eq!(result, VoteWindowResult::NotOpen);
    }

    #[tokio::test]
    async fn already_closed_after_voting_window_passes() {
        let service = setup_service(example_eras()).await;

        // epoch 0's window [1100, 1180) has closed by 1190, while `now` is still inside epoch
        // 1's span [1100, 1200).
        let result = service
            .get_votes_for_current_vote_window(1190)
            .await
            .expect("computes vote window");

        assert_eq!(result, VoteWindowResult::AlreadyClosed);
    }

    #[tokio::test]
    async fn votes_with_no_recorded_requests_are_empty() {
        let service = setup_service(example_eras()).await;

        // past submit_after (1105), still inside the window (closes at 1180).
        let result = service
            .get_votes_for_current_vote_window(1110)
            .await
            .expect("computes vote window");

        assert_eq!(
            result,
            VoteWindowResult::Vote {
                epoch: 0,
                counts: vec![]
            }
        );
    }

    #[tokio::test]
    async fn votes_aggregate_recorded_requests_by_rp_id() {
        let service = setup_service(example_eras()).await;

        // requests for both epoch 0 [1000, 1100) and epoch 1 [1100, 1200), to check that each
        // epoch's vote only counts its own requests.
        service
            .record_rp_request_batch(vec![
                request(5, 1, 1010),
                request(5, 2, 1020),
                request(7, 3, 1030),
                request(9, 4, 1150),
            ])
            .await
            .expect("requests are recorded");

        let epoch0 = service
            .get_votes_for_current_vote_window(1110)
            .await
            .expect("computes vote window");
        assert_eq!(
            epoch0,
            VoteWindowResult::Vote {
                epoch: 0,
                counts: vec![RpCount { rpId: 5, count: 2 }, RpCount { rpId: 7, count: 1 }],
            }
        );

        // epoch 1's window is [1200, 1280); submit_after is 1205.
        let epoch1 = service
            .get_votes_for_current_vote_window(1210)
            .await
            .expect("computes vote window");
        assert_eq!(
            epoch1,
            VoteWindowResult::Vote {
                epoch: 1,
                counts: vec![RpCount { rpId: 9, count: 1 }],
            }
        );
    }

    #[tokio::test]
    async fn nonce_can_be_reused_only_across_different_epochs() {
        let service = setup_service(example_eras()).await;

        // rp 13's nonce 99 is used twice within epoch 0's span [1000, 1100) — the second is a
        // replay and must not be double-counted — and once more in epoch 1's span
        // [1100, 1200), where reusing the same (rp_id, nonce) pair is fine since the
        // uniqueness constraint is scoped per epoch.
        service
            .record_rp_request_batch(vec![
                request(13, 99, 1010),
                request(13, 99, 1020),
                request(13, 99, 1150),
            ])
            .await
            .expect("requests are recorded");

        let epoch0 = service
            .get_votes_for_current_vote_window(1110)
            .await
            .expect("computes vote window");
        assert_eq!(
            epoch0,
            VoteWindowResult::Vote {
                epoch: 0,
                counts: vec![RpCount { rpId: 13, count: 1 }],
            }
        );

        // epoch 1's window is [1200, 1280); submit_after is 1205.
        let epoch1 = service
            .get_votes_for_current_vote_window(1210)
            .await
            .expect("computes vote window");
        assert_eq!(
            epoch1,
            VoteWindowResult::Vote {
                epoch: 1,
                counts: vec![RpCount { rpId: 13, count: 1 }],
            }
        );
    }

    #[tokio::test]
    async fn not_ready_before_submit_after_at_era_boundary() {
        let service = setup_service(example_eras()).await;

        // epoch 2's window opens exactly at era 1's start (1300) with era 1's votingWindow (40),
        // but submit_after (1300+5=1305) hasn't passed yet.
        let result = service
            .get_votes_for_current_vote_window(1301)
            .await
            .expect("computes vote window");

        assert_eq!(result, VoteWindowResult::NotOpen);
    }

    #[tokio::test]
    async fn already_closed_for_epoch_governed_by_era_boundary_window() {
        let service = setup_service(example_eras()).await;

        // epoch 2's window [1300, 1340) has closed by 1345, while `now` is still inside epoch
        // 3's span [1300, 1350).
        let result = service
            .get_votes_for_current_vote_window(1345)
            .await
            .expect("computes vote window");

        assert_eq!(result, VoteWindowResult::AlreadyClosed);
    }

    #[tokio::test]
    async fn votes_isolate_requests_across_era_boundary() {
        let service = setup_service(example_eras()).await;

        // requests for both epoch 2's era-0 span [1200, 1300) and epoch 3's era-1 span
        // [1300, 1350), to check that each epoch's vote only counts its own requests, even
        // across the era boundary.
        service
            .record_rp_request_batch(vec![
                request(9, 1, 1250),
                request(9, 2, 1260),
                request(4, 3, 1270),
                request(11, 4, 1310),
                request(11, 5, 1320),
            ])
            .await
            .expect("requests are recorded");

        // epoch 2 [1200, 1300) is still era-0 span, but its window [1300, 1340) is era-1's,
        // since the window opens exactly at the era boundary.
        let epoch2 = service
            .get_votes_for_current_vote_window(1310)
            .await
            .expect("computes vote window");
        assert_eq!(
            epoch2,
            VoteWindowResult::Vote {
                epoch: 2,
                counts: vec![RpCount { rpId: 4, count: 1 }, RpCount { rpId: 9, count: 2 }],
            }
        );

        // epoch 3 [1300, 1350) is fully governed by era 1; its window is [1350, 1390).
        let epoch3 = service
            .get_votes_for_current_vote_window(1360)
            .await
            .expect("computes vote window");
        assert_eq!(
            epoch3,
            VoteWindowResult::Vote {
                epoch: 3,
                counts: vec![RpCount { rpId: 11, count: 2 }],
            }
        );
    }
}
