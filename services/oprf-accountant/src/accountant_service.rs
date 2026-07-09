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

use std::{
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};

use alloy::{
    primitives::Address,
    providers::DynProvider,
    signers::{Signer as _, local::PrivateKeySigner},
    sol,
    sol_types::{Eip712Domain, SolStruct as _, eip712_domain},
};
use eyre::Context;
use taceo_nodes_common::web3::HttpRpcProvider;
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
        // (`[start, end)`), the timestamp its voting window closes at, and whether `signer`
        // already voted for it. `exists` is false only before the very first epoch has elapsed
        // (protocol genesis, i.e. epoch 0 is still in progress), in which case the other fields
        // are meaningless.
        //
        // Not yet implemented on `BillingContract` (pending PR); mirrors `_latestClosedEpoch`'s
        // era walk, but keys off `era.startTime` (an epoch's own span start) instead of the
        // voting-window close, then simply calls `epochEnd`/`votingWindowEnd` for the epoch
        // found. Bundles in the `hasVoted` check for `signer` so callers don't need a second
        // contract call to find out whether they still need to vote:
        //
        //   function currentVoteEpoch(address signer)
        //       external view virtual onlyProxy onlyInitialized
        //       returns (
        //           bool exists,
        //           uint32 epoch,
        //           uint64 start,
        //           uint64 end,
        //           uint64 votingWindowEnd,
        //           bool alreadyVoted
        //       )
        //   {
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
        //           if (e == 0) return (false, 0, 0, 0, 0, false); // epoch 0 still in progress: nothing elapsed yet
        //           if (e - 1 > type(uint32).max) revert EpochTooLarge();
        //           epoch = uint32(e - 1); // the latest fully-elapsed epoch
        //           start = epoch >= 1 ? epochEnd(epoch - 1) : 0;
        //           end = epochEnd(epoch);
        //           votingWindowEnd = votingWindowEnd(epoch);
        //           alreadyVoted = _submitterState[epoch][signer].hasVoted;
        //           return (true, epoch, start, end, votingWindowEnd, alreadyVoted);
        //       }
        //       return (false, 0, 0, 0, 0, false); // fresh deployment: epoch 0 still in progress
        //   }
        function currentVoteEpoch(address signer)
            external
            view
            returns (
                bool exists,
                uint32 epoch,
                uint64 start,
                uint64 end,
                uint64 votingWindowEnd,
                bool alreadyVoted
            );

        // The timestamp at which epoch `epoch` ends (and its voting window opens). Defined for
        // every epoch, past or future; already implemented on `BillingContract`. Used to know
        // exactly when to check back for the next vote-able epoch, instead of polling blindly.
        function epochEnd(uint32 epoch) external view returns (uint64);

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

/// Aggregates recorded RP request counts per epoch and submits them as billing votes.
///
/// Constructed via [`OprfAccountantService::new`]; driven by repeatedly calling
/// [`OprfAccountantService::tick`] (typically via [`OprfAccountantService::run`]).
#[derive(Clone)]
pub(crate) struct OprfAccountantService {
    contract: IBillingContractInstance<DynProvider>,
    billing_contract: Address,
    chain_id: u64,
    signer: PrivateKeySigner,
    db: PostgresDb,
    voting_window_offset: Duration,
    billing_vote_chunk_size: NonZeroUsize,
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

        loop {
            tokio::select! {
                res = self.tick() => {
                    if let Err(err) = res {
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

    #[instrument(level = "info", skip_all, name = "accountant_service::tick")]
    pub(crate) async fn tick(&self) -> eyre::Result<()> {
        let vote_epoch_info = self
            .contract
            .currentVoteEpoch(self.signer.address())
            .call()
            .await?;
        if !vote_epoch_info.exists {
            // Epoch 0 hasn't elapsed yet, nothing to vote for. Wait until it does, then
            // start over so we re-read the current vote epoch from the contract.
            let epoch_0_end = self.contract.epochEnd(0).call().await?;
            tracing::info!("no epochs have elapsed yet, waiting for epoch 0 to elapse");
            // We add a 10 second buffer to the sleep time to ensure we land after the epoch has ended.
            sleep_until(epoch_0_end + 10).await;
            return Ok(());
        }

        let vote_epoch = vote_epoch_info.epoch;
        let epoch_span = vote_epoch_info.start..vote_epoch_info.end;

        if vote_epoch_info.alreadyVoted {
            // Already voted for this epoch. Wait until the epoch currently in
            // progress (`vote_epoch + 1`) also elapses (plus a buffer, to be safe against clock
            // drift), then start over so we re-read the current vote epoch from the contract.
            let next_epoch_end = self.contract.epochEnd(vote_epoch + 1).call().await?;
            tracing::trace!(vote_epoch, "already voted; waiting for the next epoch");
            sleep_until(next_epoch_end + 10).await;
            return Ok(());
        }

        // Not yet voted: wait for the voting window (+ offset) to open, then vote.
        sleep_until(epoch_span.end + self.voting_window_offset.as_secs()).await;

        // Aggregate the recorded RP request counts for the epoch span.
        let counts = self.db.rp_counts_for_epoch_span(&epoch_span).await?;
        tracing::info!(?counts, "collected counts for epoch span");

        // Max time we can spend voting for this epoch, from now until the voting window closes.
        let remaining_voting_window = Duration::from_secs(
            vote_epoch_info
                .votingWindowEnd
                .saturating_sub(now_unix_timestamp()),
        );
        tokio::time::timeout(
            remaining_voting_window,
            self.vote_for_epoch(vote_epoch, counts),
        )
        .await??;
        tracing::info!(vote_epoch, "successfully voted for epoch");

        Ok(())
    }
}

/// Returns the current unix timestamp in seconds.
fn now_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_secs()
}

/// Sleeps until `target` (a unix timestamp in seconds), or returns immediately if it's already
/// in the past.
async fn sleep_until(target: u64) {
    let sleep_duration = Duration::from_secs(target.saturating_sub(now_unix_timestamp()));
    tracing::info!(?sleep_duration, target, "sleeping until target timestamp");
    tokio::time::sleep(sleep_duration).await;
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
/// for `epoch` even when it observed nothing, since `hasVoted` is only set by a submitted vote.
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
    use std::num::NonZeroUsize;

    use alloy::{primitives::Address, signers::local::PrivateKeySigner, sol_types::SolStruct as _};

    use super::{BillingVoteChunk, RpCount, billing_vote_domain, build_signed_vote_chunks};

    fn rp_counts(n: u64) -> Vec<RpCount> {
        (1..=n).map(|i| RpCount { rpId: i, count: i }).collect()
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
