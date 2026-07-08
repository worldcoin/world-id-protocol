// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IBillingContract
 * @author World Contributors
 * @notice Interface for the World ID Billing Contract (WIP-107).
 * @dev The Billing Contract settles per-epoch usage fees that a Relying Party (RP) pays to the
 *      protocol for Uniqueness Proofs. OPRF nodes count unique RP requests per epoch, EIP-712-sign
 *      their tally as one or more {BillingVoteChunk}s, and submit the chunks on-chain. The contract finalizes the
 *      lower-median count across the node set (gated on quorum), prices it through a tiered WLD fee
 *      schedule, and accrues per-RP debt. RPs whose oldest unpaid epoch is past its payment window
 *      are surfaced as blocked so OPRF nodes can refuse further service.
 */
interface IBillingContract {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    /// @notice A single (rpId, count) entry inside a node's billing vote.
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

    /// @notice A single RP's payment instruction.
    struct RpPayment {
        // the Relying Party whose finalized debt is being settled.
        uint64 rpId;
        // settle this RP's finalized debt up to and including this epoch.
        uint32 uptoEpoch;
        // slippage guard: revert if the selected debt exceeds this amount.
        // use type(uint256).max for an unconditional payment.
        uint256 maxAmount;
    }

    /// @notice One timing era: the epoch parameters in force from `startEpoch` on.
    /// @dev Eras are kept as an append-only history (one entry per timing change), so every epoch
    ///      that ever existed keeps its true boundaries, voting window, and payment deadline.
    ///
    ///      An era's parameters govern its *timespan* `[startTime, nextEra.startTime)`: epoch
    ///      spans lying in it use its `epochLength`; voting windows *opening* in it use its
    ///      `votingWindow` and `paymentWindow`. Since votes for an epoch are cast after it ends,
    ///      the window of the last epoch before an era change opens exactly at the era boundary
    ///      and is thus governed by the new era, this keeps window closes monotone in epoch
    ///      number across changes (given `votingWindow <= epochLength`), which finalization
    ///      relies on.
    ///
    ///      Example: era 0 = `{startEpoch: 0, startTime: 1000, len: 100, vote: 80, pay: 200}`,
    ///      and `setTiming(50, 40, 100)` is called at t=1250 (inside epoch 2), appending
    ///      era 1 = `{startEpoch: 3, startTime: 1300, len: 50, vote: 40, pay: 100}`:
    ///
    ///        epoch 1 [1100, 1200) | window [1200, 1280) | due 1480   era-0 span, era-0 window
    ///        epoch 2 [1200, 1300) | window [1300, 1340) | due 1440   era-0 span, era-1 window
    ///        epoch 3 [1300, 1350) | window [1350, 1390) | due 1490   era-1 span, era-1 window
    ///
    ///      Epoch 2 keeps its old length (its span lies in era 0), while its window — opening at
    ///      the boundary — uses the new parameters. Epoch 1's window, already open at the change,
    ///      is untouched and closes at its historic time.
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

    /// @notice A single tier in the marginal fee schedule.
    /// @dev Tiers are ordered by ascending `upTo`; the final tier MUST use `type(uint256).max`.
    ///      Rates are strictly decreasing (volume discount). `rate` is WLD wei per request.
    struct Tier {
        // cumulative request boundary this tier covers up to (inclusive).
        uint256 upTo;
        // marginal price in WLD wei for each request that falls into this tier.
        uint256 rate;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /// @dev Thrown when submitting votes for an epoch whose voting window has not opened yet.
    error VotingWindowNotOpen();

    /// @dev Thrown when submitting votes for an epoch whose voting window has already closed.
    error VotingWindowClosed();

    /// @dev Thrown when a recovered signer has already closed their chunked vote for the epoch.
    error VoteAlreadyClosed();

    /// @dev Thrown when a chunk does not match the signer's next expected chunk index.
    error UnexpectedChunkIndex();

    /// @dev Thrown when a recovered signer is not part of the live OPRF node set.
    error NotANode();

    /// @dev Thrown when a vote's counts are not strictly ascending by rpId (also rejects duplicates).
    error CountsNotAscending();

    /// @dev Thrown when a vote includes a zero count (zero counts must be omitted, not encoded).
    error ZeroCount();

    /// @dev Thrown when an RP's outstanding debt exceeds the caller-supplied `maxAmount`.
    error DebtExceedsMax();

    /// @dev Thrown when a submitted tier schedule is malformed.
    error InvalidTierSchedule();

    /// @dev Thrown when timing parameters violate the `votingWindow <= epochLength` invariant or are zero.
    error InvalidTiming();

    /// @dev Thrown when a timestamp-derived epoch exceeds the uint32 epoch domain, or an epoch's
    ///      end exceeds the uint64 timestamp domain.
    error EpochTooLarge();

    /// @dev Thrown when rebate-period accounting cannot fit in the packed period state.
    error PeriodStateOverflow();

    /// @dev Thrown when a finalized epoch fee cannot fit in the packed unpaid-epoch state.
    error FeeOverflow();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /// @notice Emitted for every RP that received a non-zero finalized count when an epoch finalizes.
    /// @dev Raw per-epoch vote data is pruned on finalization, so this event is the canonical
    ///      off-chain record of finalized counts for audit/indexing.
    /// @param epoch The finalized epoch.
    /// @param rpId The Relying Party.
    /// @param count The finalized (lower-median) request count.
    /// @param fee The WLD fee accrued for the RP in this epoch.
    event EpochRpFinalized(uint32 indexed epoch, uint64 indexed rpId, uint64 count, uint256 fee);

    /// @notice Emitted when an RP's outstanding debt is settled.
    /// @param rpId The Relying Party.
    /// @param payer The address that funded the payment.
    /// @param uptoEpoch The highest epoch the payment attempted to settle.
    /// @param amount The WLD amount transferred to the fee recipient.
    event DebtPaid(uint64 indexed rpId, address indexed payer, uint32 uptoEpoch, uint256 amount);

    /// @notice Emitted when the tier schedule is replaced.
    event TierScheduleUpdated();

    /// @notice Emitted when the OPRF key registry address is updated.
    /// @param oldOprfKeyRegistry The previous registry address.
    /// @param newOprfKeyRegistry The new registry address.
    event OprfKeyRegistryUpdated(address oldOprfKeyRegistry, address newOprfKeyRegistry);

    /// @notice Emitted when the epoch timing parameters are updated.
    /// @dev OPRF nodes must re-derive their vote schedule from the new era: epoch boundaries from
    ///      `eraStartEpoch` on are `eraStartTime + (epoch + 1 - eraStartEpoch) * epochLength`.
    ///      Existing epochs are unaffected; their windows close at their original times.
    /// @param epochLength The new epoch length in seconds.
    /// @param votingWindow The new voting window in seconds.
    /// @param paymentWindow The new payment window in seconds.
    /// @param eraStartEpoch The first epoch governed by the new parameters.
    /// @param eraStartTime The era start: end of epoch `eraStartEpoch - 1`, unchanged by the update.
    event TimingUpdated(
        uint64 epochLength, uint64 votingWindow, uint64 paymentWindow, uint32 eraStartEpoch, uint64 eraStartTime
    );

    /// @notice Emitted when the rebate (volume-discount) period length is updated.
    /// @param rebatePeriodEpochs The new number of epochs per rebate period.
    event RebatePeriodUpdated(uint32 rebatePeriodEpochs);

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Submit one or more OPRF node billing vote chunks for a single epoch.
     * @dev Records votes only; does not finalize as a side effect (finalization is driven solely by
     *      {finalizeEpochs}), so a node's vote gas never carries another epoch's finalization cost.
     *      Quorum and pricing are read live at finalization (no per-epoch snapshot). Authenticates
     *      by recovered signer, not msg.sender. A node's chunks must be submitted in order and the
     *      node counts toward quorum only after its final chunk is accepted.
     * @param epoch The epoch the vote chunks are cast for; its voting window must be currently open.
     * @param chunks The signed vote chunks to record.
     */
    function submitBillingVotes(uint32 epoch, SignedVoteChunk[] calldata chunks) external;

    /**
     * @notice Settle finalized debt for one or more RPs through caller-selected epochs.
     * @dev Permissionless; settles currently-finalized debt and does not finalize as a side effect
     *      (call {finalizeEpochs} first if closed epochs must be reflected). All-or-nothing per
     *      instruction: pays the debt through `uptoEpoch` or reverts if it exceeds the RP's
     *      `maxAmount` guard. Pulls WLD from msg.sender to the fee recipient.
     * @param payments The per-RP payment instructions.
     */
    function pay(RpPayment[] calldata payments) external;

    /**
     * @notice Permissionlessly finalize closed epochs up to (and including) `uptoEpoch`.
     * @dev Flushes the tail when node votes have stopped, so debt and `isBlocked` stay current.
     *      Chunkable: advances the global cursor by at most `maxSteps` units (one per RP finalized,
     *      one per epoch closed), resuming mid-epoch across calls so a large epoch never bricks.
     * @param uptoEpoch The highest epoch to finalize up to; capped at the latest closed epoch.
     * @param maxSteps The maximum units of finalization work to perform in this call.
     */
    function finalizeEpochs(uint32 uptoEpoch, uint256 maxSteps) external;

    /**
     * @notice Replace the tier schedule. Applies to every not-yet-finalized epoch (no versioning).
     * @dev Owner only. Rates must be strictly decreasing, `upTo` strictly ascending, last `upTo`
     *      equal to type(uint256).max.
     * @param tiers The new tier schedule.
     */
    function setTierSchedule(Tier[] calldata tiers) external;

    /**
     * @notice Update the epoch timing parameters.
     * @dev Owner only. Re-checks the `votingWindow <= epochLength` invariant. Starts a new era at
     *      the end of the in-flight epoch: the new parameters govern later epochs only, and no
     *      existing epoch is affected in any way — boundaries, open voting windows, and payment
     *      deadlines all keep their original, era-true values (the full era history is retained).
     *      If the previous change's era has not started yet, its parameters are updated in place
     *      instead. Closed-but-unfinalized epochs finalize normally; a change never delays them.
     * @param epochLength The epoch length in seconds.
     * @param votingWindow The voting window in seconds.
     * @param paymentWindow The payment window in seconds.
     */
    function setTiming(uint64 epochLength, uint64 votingWindow, uint64 paymentWindow) external;

    /**
     * @notice Update the OPRF key registry the node set is read from.
     * @dev Owner only.
     * @param newOprfKeyRegistry The new OPRF key registry address.
     */
    function updateOprfKeyRegistry(address newOprfKeyRegistry) external;

    /**
     * @notice Update the rebate (volume-discount) period length.
     * @dev Owner only. Changing the divisor shifts period boundaries, so the running per-RP period
     *      count resets on each RP's next finalization; coordinate the change at a period boundary.
     * @param rebatePeriodEpochs The new number of epochs per rebate period (must be non-zero).
     */
    function setRebatePeriodEpochs(uint32 rebatePeriodEpochs) external;

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Whether an RP is blocked for non-payment.
     * @dev O(1). True when the RP has outstanding finalized debt whose oldest unpaid epoch is past
     *      its payment window. Reflects finalized state only; tail epochs become billable after a
     *      `finalizeEpochs`/`pay`/`submitBillingVotes` call advances finalization. Deadlines are
     *      era-true and permanent: each epoch's payment deadline derives from the parameters of
     *      the era its voting window belongs to, so timing changes never move any existing
     *      deadline in either direction.
     * @param rpId The Relying Party.
     * @return Whether the RP is currently blocked.
     */
    function isBlocked(uint64 rpId) external view returns (bool);

    /**
     * @notice The lower-median request count for an RP in a retained (not-yet-finalized) epoch.
     * @dev Finalized epochs are pruned and return 0; their counts are available via {EpochRpFinalized}.
     * @param epoch The epoch.
     * @param rpId The Relying Party.
     * @return The lower-median count, or 0 if below quorum / pruned / unseen.
     */
    function epochRequestCount(uint32 epoch, uint64 rpId) external view returns (uint64);

    /**
     * @notice The current outstanding (finalized) debt for an RP in WLD wei.
     * @param rpId The Relying Party.
     * @return The outstanding debt.
     */
    function outstandingDebt(uint64 rpId) external view returns (uint256);

    /**
     * @notice The latest epoch that has been fully finalized, if any.
     * @dev Finalization work is pending whenever this trails {latestClosedEpoch} (including the case
     *      where nothing is finalized yet but some epoch has closed). Off-chain keepers poll this
     *      together with {latestClosedEpoch} to decide whether {finalizeEpochs} needs to be called,
     *      instead of blind-firing transactions.
     * @return exists Whether any epoch has been finalized yet.
     * @return epoch The latest finalized epoch; only meaningful when `exists` is true.
     */
    function latestFinalizedEpoch() external view returns (bool exists, uint32 epoch);

    /**
     * @notice The latest epoch whose voting window has fully closed, if any.
     * @dev Closed epochs are exactly the ones {finalizeEpochs} can finalize.
     * @return exists Whether any epoch's voting window has closed yet.
     * @return epoch The latest closed epoch; only meaningful when `exists` is true.
     */
    function latestClosedEpoch() external view returns (bool exists, uint32 epoch);

    /// @notice The EIP-712 domain separator.
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /// @notice The EIP-712 typehash for a billing vote chunk.
    function BILLING_VOTE_CHUNK_TYPEHASH() external view returns (bytes32);

    /**
     * @notice The current tier schedule.
     * @return The ordered tier schedule.
     */
    function getTierSchedule() external view returns (Tier[] memory);

    /**
     * @notice The number of epochs in a rebate (volume-discount) period.
     * @return The rebate period length in epochs.
     */
    function getRebatePeriodEpochs() external view returns (uint32);

    /**
     * @notice The current era's timing parameters and start.
     * @dev Epoch boundaries from `eraStartEpoch` on are
     *      `eraStartTime + (epoch + 1 - eraStartEpoch) * epochLength`.
     * @return epochLength The epoch length in seconds.
     * @return votingWindow The voting window in seconds.
     * @return paymentWindow The payment window in seconds.
     * @return eraStartEpoch The first epoch governed by the current parameters.
     * @return eraStartTime The era start: end of epoch `eraStartEpoch - 1`.
     */
    function getTiming()
        external
        view
        returns (
            uint64 epochLength,
            uint64 votingWindow,
            uint64 paymentWindow,
            uint32 eraStartEpoch,
            uint64 eraStartTime
        );

    /**
     * @notice The full timing-era history, oldest first; the last entry is the current era.
     * @return The eras.
     */
    function getEras() external view returns (TimingEra[] memory);
}
