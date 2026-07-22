//! Aggregates recorded RP (relying party) OPRF request counts per epoch and submits them as
//! billing votes to the `BillingContract`.
//!
//! [`OprfAccountantService::run`] drives this in a loop: each [`OprfAccountantService::tick`]
//! asks the `BillingContract` for the latest epoch whose own span has fully elapsed, together
//! with its span and voting-window close, via a single `currentVoteEpoch()` call — the contract
//! is the one source of truth for era/epoch timing, so this service does no era bookkeeping of
//! its own. It then
//! sleeps until the voting window opens (plus a configured offset, giving OPRF nodes time to
//! flush their batched requests), aggregates that epoch's recorded requests — those whose
//! `expires_at` falls within the epoch's own span — by RP id (via
//! [`PostgresDb::rp_counts_for_epoch_span`]), and submits the resulting counts as this node's
//! vote. Whether this node already voted for an epoch is read straight from the
//! `BillingContract` (bundled into the `currentVoteEpoch()` call), so a restart re-derives
//! progress from chain state.

use std::{num::NonZeroUsize, time::Duration};

use alloy::{
    primitives::Address,
    providers::DynProvider,
    signers::{Signer as _, local::PrivateKeySigner},
    sol,
    sol_types::{Eip712Domain, SolStruct as _, eip712_domain},
};
use eyre::Context;
use taceo_nodes_common::web3::HttpRpcProvider;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{accountant_service::IBillingContract::IBillingContractInstance, postgres::PostgresDb};

// TODO replace with abi
sol! {
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
    #[derive(Debug, PartialEq, Eq)]
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
        // The latest epoch whose own span has fully elapsed, if any, together with that span
        // (`[epochStart, epochEnd)`), the timestamp its voting window closes at, whether `signer` already
        // voted for it, and the current block timestamp. `exists` is false only before the very
        // first epoch has elapsed (protocol genesis, i.e. epoch 0 is still in progress), in which
        // case the other fields are meaningless. `blockTime` is meaningful regardless of `exists`.
        //
        // Not yet implemented on `BillingContract` (pending PR); mirrors `_latestClosedEpoch`'s
        // era walk, but keys off `era.startTime` (an epoch's own span start) instead of the
        // voting-window close, then simply calls `epochEnd`/`votingWindowEnd` for the epoch
        // found. Bundles in the `hasVoted` check for `signer` so callers don't need a second
        // contract call to find out whether they still need to vote, and returns `block.timestamp`
        // directly so callers don't need a separate call (e.g. `eth_getBlockByNumber`) to learn
        // the chain's current time:
        //
        //   function currentVoteEpoch(address signer)
        //       external view virtual onlyProxy onlyInitialized
        //       returns (
        //           bool exists,
        //           uint32 epoch,
        //           uint64 epochStart,
        //           uint64 epochEnd,
        //           uint64 votingWindowEnd,
        //           bool alreadyVoted,
        //           uint64 blockTime
        //       )
        //   {
        //       blockTime = uint64(block.timestamp);
        //       uint256 i = _timingEras.length;
        //       while (i > 0) {
        //           unchecked { i--; }
        //           TimingEra storage era = _timingEras[i];
        //           if (block.timestamp < era.startTime) continue; // this era hasn't started yet
        //
        //           uint256 k = (block.timestamp - era.startTime) / era.epochLength;
        //           uint256 e = uint256(era.startEpoch) + k; // the in-progress epoch
        //
        //           if (i + 1 < _timingEras.length) {
        //               uint256 regimeLastEpoch = _timingEras[i + 1].startEpoch - 1;
        //               if (e > regimeLastEpoch) e = regimeLastEpoch; // clamp into this era's own regime
        //           }
        //
        //           if (e == 0) return (false, 0, 0, 0, 0, false, blockTime); // epoch 0 still in progress: nothing elapsed yet
        //           if (e - 1 > type(uint32).max) revert EpochTooLarge();
        //           epoch = uint32(e - 1); // the latest fully-elapsed epoch
        //           epochStart = epoch >= 1 ? epochEnd(epoch - 1) : _timingEras[0].startTime; // get epoch 0 start from _timingEras
        //           epochEnd = this.epochEnd(epoch);
        //           votingWindowEnd = votingWindowEnd(epoch);
        //           alreadyVoted = _submitterState[epoch][signer].hasVoted;
        //           return (true, epoch, epochStart, epochEnd, votingWindowEnd, alreadyVoted, blockTime);
        //       }
        //       return (false, 0, 0, 0, 0, false, blockTime); // fresh deployment: epoch 0 still in progress
        //   }
        function currentVoteEpoch(address signer)
            external
            view
            returns (
                bool exists,
                uint32 epoch,
                uint64 epochStart,
                uint64 epochEnd,
                uint64 votingWindowEnd,
                bool alreadyVoted,
                uint64 blockTime
            );

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

/// The outcome of [`OprfAccountantService::maybe_get_votes`] checking whether there's an epoch
/// this node should vote for right now.
#[derive(Debug, PartialEq, Eq)]
enum MaybeVotes {
    /// No epoch is currently vote-able: either epoch 0 hasn't elapsed yet, or the latest elapsed
    /// epoch's voting window (plus [`OprfAccountantServiceArgs::voting_window_offset`]) hasn't
    /// opened yet.
    WindowNotOpen,
    /// The latest elapsed epoch's voting window has already closed without this node voting for
    /// it; the epoch can no longer be voted on.
    WindowClosed,
    /// This node already voted for the latest elapsed epoch, per the `BillingContract`.
    AlreadyVoted,
    /// The voting window for `epoch` is open and this node hasn't voted yet; `counts` are the
    /// aggregated per-RP counts to submit.
    Votes { epoch: u32, counts: Vec<RpCount> },
}

/// Aggregates recorded RP request counts per epoch and submits them as billing votes.
///
/// Constructed via [`OprfAccountantService::new`]; driven by repeatedly calling
/// [`OprfAccountantService::tick`] (typically via [`OprfAccountantService::run`]).
#[derive(Clone)]
pub(crate) struct OprfAccountantService {
    /// Binding to the `BillingContract`, built from the args' `provider` and `billing_contract`.
    contract: IBillingContractInstance<DynProvider>,
    /// Address of the `BillingContract`, used to derive the EIP-712 domain for vote signing.
    billing_contract: Address,
    /// Chain id `contract` is connected to, used to derive the EIP-712 domain for vote signing.
    chain_id: u64,
    /// Signer this node uses to sign its billing votes.
    signer: PrivateKeySigner,
    /// Database storing recorded RP requests, aggregated per epoch for voting.
    db: PostgresDb,
    /// How often [`Self::run`] calls [`Self::tick`].
    tick_interval: Duration,
    /// The maximum time to wait for a `submitBillingVotes` transaction to be confirmed.
    vote_timeout: Duration,
    /// Extra delay after an epoch's voting window opens before aggregating and voting for it.
    voting_window_offset: Duration,
    /// The maximum number of `RpCount`s per `SignedVoteChunk` submitted to `submitBillingVotes`.
    billing_vote_chunk_size: NonZeroUsize,
    /// Signals [`Self::run`] to stop.
    cancellation_token: CancellationToken,
}

/// Construction parameters for [`OprfAccountantService::new`].
pub(crate) struct OprfAccountantServiceArgs {
    /// Provider used to call and sign transactions against the `BillingContract`.
    pub(crate) provider: HttpRpcProvider,
    /// Chain id `provider` is connected to.
    pub(crate) chain_id: u64,
    /// Address of the `BillingContract`.
    pub(crate) billing_contract: Address,
    /// Signer this node uses to sign its billing votes.
    pub(crate) signer: PrivateKeySigner,
    /// Database storing recorded RP requests.
    pub(crate) db: PostgresDb,
    /// How often to call [`OprfAccountantService::tick`] in [`OprfAccountantService::run`].
    /// Needs to be smaller than the current era's `votingWindow` so we don't miss the voting window
    pub(crate) tick_interval: Duration,
    /// The maximum time to wait for a `submitBillingVotes` transaction to be confirmed.
    pub(crate) vote_timeout: Duration,
    /// Extra delay after an epoch's voting window opens before we aggregate and vote for it,
    /// giving OPRF nodes time to flush their batched requests to us. Should be kept well below
    /// the current era's `votingWindow`: [`OprfAccountantService::tick`] only has whatever time
    /// remains until `votingWindowEnd` to submit the vote once it wakes up, so too large an
    /// offset leaves no time to vote and the epoch's `submitBillingVotes` call times out.
    pub(crate) voting_window_offset: Duration,
    /// The maximum number of `RpCount`s per `SignedVoteChunk` submitted to `submitBillingVotes`.
    pub(crate) billing_vote_chunk_size: NonZeroUsize,
    /// Signals [`OprfAccountantService::run`] to stop.
    pub(crate) cancellation_token: CancellationToken,
}

impl OprfAccountantService {
    /// Constructs the service, building the `BillingContract` binding from `provider` and
    /// `billing_contract`.
    pub(crate) fn new(
        OprfAccountantServiceArgs {
            provider,
            chain_id,
            billing_contract,
            signer,
            db,
            tick_interval,
            vote_timeout,
            voting_window_offset,
            billing_vote_chunk_size,
            cancellation_token,
        }: OprfAccountantServiceArgs,
    ) -> Self {
        let contract = IBillingContract::new(billing_contract, provider.inner());
        Self {
            contract,
            billing_contract,
            chain_id,
            signer,
            db,
            tick_interval,
            vote_timeout,
            voting_window_offset,
            billing_vote_chunk_size,
            cancellation_token,
        }
    }

    /// Runs the service until `cancellation_token` is cancelled, immediately starting the next
    /// [`Self::tick`] as soon as the previous one returns.
    ///
    /// A tick that returns an error is logged and retried on the next tick rather than stopping
    /// the loop, since a transient failure (e.g. a dropped DB connection) shouldn't prevent
    /// later epochs from being voted on.
    pub(crate) async fn run(&self) {
        tracing::info!("starting OprfAccountant worker");

        let mut interval = tokio::time::interval(self.tick_interval);
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

    /// Submits `counts` as this node's billing vote for `epoch`. Still submits a single chunk
    /// with an empty `counts` when `counts` is itself empty — whether this node already voted
    /// for `epoch` is tracked by the contract only via a submitted vote, so a real (if empty)
    /// vote is required for `tick` to see this epoch as done and not retry it forever.
    ///
    /// Splits `counts` into `billing_vote_chunk_size`-sized [`SignedVoteChunk`]s (see
    /// [`build_signed_vote_chunks`]), then submits each chunk for `epoch` in its own
    /// `submitBillingVotes` call.
    ///
    /// # Errors
    /// Returns an error if signing a chunk fails, if a `submitBillingVotes` transaction fails to
    /// send or confirm, or if a transaction reverts.
    #[instrument(
        level = "info",
        skip_all,
        fields(epoch),
        name = "accountant_service::vote_for_epoch"
    )]
    async fn vote_for_epoch(&self, epoch: u32, counts: Vec<RpCount>) -> eyre::Result<()> {
        let domain = billing_vote_domain(self.chain_id, self.billing_contract);

        let signed_chunks = build_signed_vote_chunks(
            &self.signer,
            &domain,
            epoch,
            counts,
            self.billing_vote_chunk_size,
        )
        .await?;

        for signed_chunk in signed_chunks {
            tracing::info!(epoch, ?signed_chunk, "submitting billing vote chunk");
            // TODO we need to implement the signing with the OPRF nodes keys but sending with a different wallet.
            // Otherwise the nonces of the KeyGen will be wrong if we use the same wallet.
            // TODO retry on failure, timeout handled by caller
            // let receipt = self
            //     .contract
            //     .submitBillingVotes(epoch, vec![signed_chunk])
            //     .send()
            //     .await
            //     .context("while submitting billing votes")?
            //     .get_receipt()
            //     .await
            //     .context("while waiting for the billing vote receipt")?;

            // if !receipt.status() {
            //     eyre::bail!("submitBillingVotes transaction reverted for epoch {epoch}");
            // }
        }

        Ok(())
    }

    /// Votes for the next vote-able epoch, if any (see [`Self::maybe_get_votes`]); a no-op if no
    /// epoch is currently vote-able.
    ///
    /// # Errors
    /// Returns an error if querying the `BillingContract` or the database fails, or if voting
    /// doesn't complete within [`OprfAccountantServiceArgs::vote_timeout`].
    #[instrument(level = "info", skip_all, name = "accountant_service::tick")]
    pub(crate) async fn tick(&self) -> eyre::Result<()> {
        if let MaybeVotes::Votes { epoch, counts } = self.maybe_get_votes().await? {
            tokio::time::timeout(self.vote_timeout, self.vote_for_epoch(epoch, counts)).await??;
            tracing::info!(epoch, "successfully voted for epoch");
        }
        Ok(())
    }

    /// Determines whether there's an epoch this node should vote for right now, and if so,
    /// aggregates its per-RP counts. See [`MaybeVotes`] for the possible outcomes.
    ///
    /// # Errors
    /// Returns an error if the `currentVoteEpoch` contract call or the count aggregation query
    /// fails.
    #[instrument(level = "info", skip_all, name = "accountant_service::maybe_get_votes")]
    async fn maybe_get_votes(&self) -> eyre::Result<MaybeVotes> {
        // Ask the contract for the latest epoch whose own span has fully elapsed,
        // together with its voting window close and whether this node already voted for it.
        let vote_epoch = self
            .contract
            .currentVoteEpoch(self.signer.address())
            .call()
            .await?;
        let epoch = vote_epoch.epoch;

        // Return if no epochs have elapsed yet (i.e. epoch 0 is still in progress). The first epoch's
        if !vote_epoch.exists {
            tracing::info!("no epochs have elapsed yet, waiting for epoch 0 to elapse");
            return Ok(MaybeVotes::WindowNotOpen);
        }

        // Return if this node already voted for the epoch, since the contract is the source of truth for
        if vote_epoch.alreadyVoted {
            tracing::info!(epoch, "already voted, waiting for next epoch");
            return Ok(MaybeVotes::AlreadyVoted);
        }

        // Return if the additional voting window offset hasn't elapsed yet. OPRF nodes need time to flush batched requests.
        if vote_epoch.blockTime < vote_epoch.epochEnd + self.voting_window_offset.as_secs() {
            tracing::info!(
                epoch,
                block_time = vote_epoch.blockTime,
                epoch_end = vote_epoch.epochEnd,
                "voting window not open yet, waiting for next tick"
            );
            return Ok(MaybeVotes::WindowNotOpen);
        }

        // Return if the voting window has already closed, since we can't vote for it anymore.
        if vote_epoch.blockTime >= vote_epoch.votingWindowEnd {
            tracing::warn!(
                epoch,
                block_time = vote_epoch.blockTime,
                voting_window_end = vote_epoch.votingWindowEnd,
                "voting window already closed without voting, waiting for next epoch"
            );
            return Ok(MaybeVotes::WindowClosed);
        }

        // Aggregate the recorded RP request counts for the epoch span.
        let counts = self
            .db
            .rp_counts_for_epoch_span(&(vote_epoch.epochStart..vote_epoch.epochEnd))
            .await?;
        tracing::info!(?counts, "collected counts for epoch span");

        Ok(MaybeVotes::Votes { epoch, counts })
    }
}

/// The EIP-712 domain of the `BillingContract` at `verifying_contract` on `chain_id`, matching
/// its `EIP712_NAME`/`EIP712_VERSION` constants.
fn billing_vote_domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain!(
        name: "BillingContract",
        version: "1.0",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    )
}

/// Splits `counts` into `chunk_size`-sized pieces and signs each as an EIP-712 `BillingVoteChunk`
/// for `epoch` with `signer`, returning the resulting [`SignedVoteChunk`]s in ascending
/// `chunkIndex` order. `isFinal` is set only on the last chunk. If `counts` is empty, returns a
/// single chunk with `isFinal = true` and an empty `counts` — the node must still record a vote
/// for `epoch` even when it observed nothing, since `alreadyVoted` is only set by a submitted vote.
///
/// # Errors
/// Returns an error if `counts` needs more than [`u32::MAX`] chunks, or if signing a chunk fails.
async fn build_signed_vote_chunks(
    signer: &PrivateKeySigner,
    domain: &Eip712Domain,
    epoch: u32,
    counts: Vec<RpCount>,
    chunk_size: NonZeroUsize,
) -> eyre::Result<Vec<SignedVoteChunk>> {
    let chunk_total = counts.len().div_ceil(chunk_size.into()).max(1);
    let mut signed_chunks = Vec::with_capacity(chunk_total);

    let chunks = if counts.is_empty() {
        vec![Vec::new()]
    } else {
        counts
            .chunks(chunk_size.into())
            .map(<[RpCount]>::to_vec)
            .collect()
    };

    for (i, chunk) in chunks.into_iter().enumerate() {
        let chunk_index = u32::try_from(i).context("too many billing vote chunks")?;
        let is_final = i + 1 == chunk_total;

        let typed_chunk = BillingVoteChunk {
            epoch,
            chunkIndex: chunk_index,
            isFinal: is_final,
            counts: chunk,
        };
        let digest = typed_chunk.eip712_signing_hash(domain);
        let signature = signer
            .sign_hash(&digest)
            .await
            .context("while signing billing vote chunk")?;

        signed_chunks.push(SignedVoteChunk {
            chunkIndex: chunk_index,
            isFinal: is_final,
            counts: typed_chunk.counts,
            signature: signature.as_bytes().to_vec().into(),
        });
    }

    Ok(signed_chunks)
}

#[cfg(test)]
mod tests {
    use std::{
        num::{NonZeroU32, NonZeroUsize},
        time::Duration,
    };

    use alloy::{
        primitives::Address,
        providers::{DynProvider, Provider as _, ProviderBuilder},
        signers::local::PrivateKeySigner,
        sol_types::{SolCall as _, SolStruct as _},
        transports::mock::Asserter,
    };
    use secrecy::SecretString;
    use taceo_nodes_common::{
        postgres::PostgresConfig,
        test_utils::{next_test_schema, shared_postgres_testcontainer},
    };
    use tokio_util::sync::CancellationToken;

    use super::{
        BillingVoteChunk, IBillingContract, MaybeVotes, OprfAccountantService, PostgresDb, RpCount,
        billing_vote_domain, build_signed_vote_chunks,
    };

    fn rp_counts(n: u64) -> Vec<RpCount> {
        (1..=n).map(|i| RpCount { rpId: i, count: i }).collect()
    }

    /// Builds a [`PostgresDb`] backed by a fresh schema in the shared testcontainer, mirroring
    /// `postgres::tests::setup_db`.
    async fn setup_db() -> PostgresDb {
        let connection_string = shared_postgres_testcontainer()
            .await
            .expect("shared postgres testcontainer starts");
        let mut db_config = PostgresConfig::with_default_values(
            SecretString::from(connection_string.to_owned()),
            next_test_schema(),
        );
        db_config.max_connections = NonZeroU32::new(1).expect("non-zero");
        PostgresDb::init(&db_config)
            .await
            .expect("postgres db initializes")
    }

    /// A [`DynProvider`] whose transport returns `response` for the single `currentVoteEpoch`
    /// call it expects to see.
    fn mock_vote_epoch_provider(response: IBillingContract::currentVoteEpochReturn) -> DynProvider {
        let asserter = Asserter::new();
        let encoded = IBillingContract::currentVoteEpochCall::abi_encode_returns(&response);
        asserter.push_success(&format!("0x{}", alloy::hex::encode(encoded)));
        ProviderBuilder::default()
            .connect_mocked_client(asserter)
            .erased()
    }

    /// Builds an [`OprfAccountantService`] whose `currentVoteEpoch` call returns `vote_epoch`
    /// exactly once, backed by a real (testcontainer) [`PostgresDb`].
    async fn test_service(
        vote_epoch: IBillingContract::currentVoteEpochReturn,
    ) -> OprfAccountantService {
        let billing_contract = Address::repeat_byte(0x11);
        let contract =
            IBillingContract::new(billing_contract, mock_vote_epoch_provider(vote_epoch));
        OprfAccountantService {
            contract,
            billing_contract,
            chain_id: 31337,
            signer: PrivateKeySigner::random(),
            db: setup_db().await,
            tick_interval: Duration::from_secs(1),
            vote_timeout: Duration::from_secs(1),
            voting_window_offset: Duration::from_secs(1),
            billing_vote_chunk_size: NonZeroUsize::new(128).expect("non-zero"),
            cancellation_token: CancellationToken::new(),
        }
    }

    fn vote_epoch(
        exists: bool,
        epoch: u32,
        epoch_start: u64,
        epoch_end: u64,
        voting_window_end: u64,
        already_voted: bool,
        block_time: u64,
    ) -> IBillingContract::currentVoteEpochReturn {
        assert!(
            !exists || (epoch_start < epoch_end),
            "epoch start must be before epoch end if it exists"
        );
        assert!(
            !exists || (epoch_end < voting_window_end),
            "epoch end must be before voting window end if it exists"
        );
        IBillingContract::currentVoteEpochReturn {
            exists,
            epoch,
            epochStart: epoch_start,
            epochEnd: epoch_end,
            votingWindowEnd: voting_window_end,
            alreadyVoted: already_voted,
            blockTime: block_time,
        }
    }

    #[tokio::test]
    async fn maybe_get_votes_returns_window_not_open_when_no_epoch_has_elapsed_yet() {
        let service = test_service(vote_epoch(false, 0, 0, 0, 0, false, 0)).await;
        let result = service.maybe_get_votes().await.expect("no db error");
        assert_eq!(result, MaybeVotes::WindowNotOpen);
    }

    #[tokio::test]
    async fn maybe_get_votes_returns_already_voted() {
        let service = test_service(vote_epoch(true, 3, 100, 200, 300, true, 250)).await;
        let result = service.maybe_get_votes().await.expect("no db error");
        assert_eq!(result, MaybeVotes::AlreadyVoted);
    }

    #[tokio::test]
    async fn maybe_get_votes_returns_window_not_open_before_the_voting_window_offset_elapses() {
        // epoch ends at 200, offset is 1s, so the window doesn't open until block time 201.
        let service = test_service(vote_epoch(true, 3, 100, 200, 300, false, 200)).await;
        let result = service.maybe_get_votes().await.expect("no db error");
        assert_eq!(result, MaybeVotes::WindowNotOpen);
    }

    #[tokio::test]
    async fn maybe_get_votes_returns_window_closed_once_voting_window_end_has_passed() {
        let service = test_service(vote_epoch(true, 3, 100, 200, 300, false, 300)).await;
        let result = service.maybe_get_votes().await.expect("no db error");
        assert_eq!(result, MaybeVotes::WindowClosed);
    }

    #[tokio::test]
    async fn maybe_get_votes_returns_votes_with_the_aggregated_counts_when_the_window_is_open() {
        let service = test_service(vote_epoch(true, 3, 100, 200, 300, false, 250)).await;
        let result = service.maybe_get_votes().await.expect("no db error");
        assert_eq!(
            result,
            MaybeVotes::Votes {
                epoch: 3,
                counts: vec![]
            }
        );
    }

    #[tokio::test]
    async fn build_signed_vote_chunks_votes_with_a_single_empty_final_chunk_for_no_counts() {
        let signer = PrivateKeySigner::random();
        let domain = billing_vote_domain(31337, Address::ZERO);

        let chunks = build_signed_vote_chunks(
            &signer,
            &domain,
            0,
            vec![],
            NonZeroUsize::new(2).expect("non-zero"),
        )
        .await
        .expect("builds chunks");

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunkIndex, 0);
        assert!(chunks[0].isFinal);
        assert!(chunks[0].counts.is_empty());
    }

    #[tokio::test]
    async fn build_signed_vote_chunks_splits_evenly_divisible_counts() {
        let signer = PrivateKeySigner::random();
        let domain = billing_vote_domain(31337, Address::ZERO);

        let chunks = build_signed_vote_chunks(
            &signer,
            &domain,
            7,
            rp_counts(4),
            NonZeroUsize::new(2).expect("non-zero"),
        )
        .await
        .expect("builds chunks");

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].chunkIndex, 0);
        assert!(!chunks[0].isFinal);
        assert_eq!(
            chunks[0].counts,
            vec![RpCount { rpId: 1, count: 1 }, RpCount { rpId: 2, count: 2 }]
        );
        assert_eq!(chunks[1].chunkIndex, 1);
        assert!(chunks[1].isFinal);
        assert_eq!(
            chunks[1].counts,
            vec![RpCount { rpId: 3, count: 3 }, RpCount { rpId: 4, count: 4 }]
        );
    }

    #[tokio::test]
    async fn build_signed_vote_chunks_puts_the_remainder_in_the_last_chunk() {
        let signer = PrivateKeySigner::random();
        let domain = billing_vote_domain(31337, Address::ZERO);

        // 5 counts over chunks of 2 -> [2, 2, 1], with only the last one final.
        let chunks = build_signed_vote_chunks(
            &signer,
            &domain,
            3,
            rp_counts(5),
            NonZeroUsize::new(2).expect("non-zero"),
        )
        .await
        .expect("builds chunks");

        assert_eq!(chunks.len(), 3);
        let sizes: Vec<usize> = chunks.iter().map(|c| c.counts.len()).collect();
        assert_eq!(sizes, vec![2, 2, 1]);

        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.chunkIndex, u32::try_from(i).unwrap());
            assert_eq!(chunk.isFinal, i == chunks.len() - 1);
        }
    }

    #[tokio::test]
    async fn build_signed_vote_chunks_single_chunk_when_smaller_than_chunk_size() {
        let signer = PrivateKeySigner::random();
        let domain = billing_vote_domain(31337, Address::ZERO);

        let chunks = build_signed_vote_chunks(
            &signer,
            &domain,
            3,
            rp_counts(3),
            NonZeroUsize::new(128).expect("non-zero"),
        )
        .await
        .expect("builds chunks");

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunkIndex, 0);
        assert!(chunks[0].isFinal);
        assert_eq!(chunks[0].counts, rp_counts(3));
    }

    #[tokio::test]
    async fn build_signed_vote_chunks_signatures_recover_to_the_signer() {
        let signer = PrivateKeySigner::random();
        let chain_id = 31337;
        let verifying_contract = Address::repeat_byte(0x42);
        let domain = billing_vote_domain(chain_id, verifying_contract);
        let epoch = 9;

        let chunks = build_signed_vote_chunks(
            &signer,
            &domain,
            epoch,
            rp_counts(5),
            NonZeroUsize::new(2).expect("non-zero"),
        )
        .await
        .expect("builds chunks");

        for chunk in chunks {
            let typed_chunk = BillingVoteChunk {
                epoch,
                chunkIndex: chunk.chunkIndex,
                isFinal: chunk.isFinal,
                counts: chunk.counts,
            };
            let digest = typed_chunk.eip712_signing_hash(&domain);

            let signature = alloy::primitives::Signature::try_from(chunk.signature.as_ref())
                .expect("valid signature bytes");
            let recovered = signature
                .recover_address_from_prehash(&digest)
                .expect("signature recovers");

            assert_eq!(recovered, signer.address());
        }
    }
}
