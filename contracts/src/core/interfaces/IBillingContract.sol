// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IBillingContract
 * @author World Contributors
 * @notice Interface for the World ID Billing Contract (WIP-107).
 * @dev The Billing Contract settles per-epoch usage fees that a Relying Party (RP) pays to the
 *      protocol for Uniqueness Proofs. OPRF nodes count unique RP requests per epoch, EIP-712-sign
 *      their tally as a {BillingVote}, and submit the votes on-chain. The contract finalizes the
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

    /// @notice One OPRF node's signed billing vote for a single epoch.
    /// @dev The signed payload is the EIP-712 `BillingVote(uint64 epoch, RpCount[] counts)` struct,
    ///      where `epoch` is supplied as the call argument shared by every vote in the batch.
    struct SignedVote {
        // the per-RP counts reported by the node, strictly ascending by rpId, all counts non-zero.
        RpCount[] counts;
        // the node's EIP-712 signature over (epoch, counts). The signer is recovered, not trusted
        // from msg.sender, so any party may relay the votes.
        bytes signature;
    }

    /// @notice A single RP's payment instruction.
    struct RpPayment {
        // the Relying Party whose outstanding debt is being settled.
        uint64 rpId;
        // slippage guard: revert if the RP's outstanding debt exceeds this amount.
        // use type(uint256).max for an unconditional payment.
        uint256 maxAmount;
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

    /// @dev Thrown when a recovered signer has already voted for the epoch.
    error AlreadyVoted();

    /// @dev Thrown when a recovered signer is not part of the live OPRF node set.
    error NotANode();

    /// @dev Thrown when a vote's counts are not strictly ascending by rpId (also rejects duplicates).
    error CountsNotAscending();

    /// @dev Thrown when a vote includes a zero count (zero counts must be omitted, not encoded).
    error ZeroCount();

    /// @dev Thrown when no OPRF nodes are registered, so quorum cannot be established.
    error NoNodesRegistered();

    /// @dev Thrown when an RP's outstanding debt exceeds the caller-supplied `maxAmount`.
    error DebtExceedsMax();

    /// @dev Thrown when a submitted tier schedule is malformed.
    error InvalidTierSchedule();

    /// @dev Thrown when timing parameters violate the `votingWindow <= epochLength` invariant or are zero.
    error InvalidTiming();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    /// @notice Emitted once per `submitBillingVotes` call.
    /// @param epoch The epoch the votes were cast for.
    /// @param count The number of votes accepted in the call.
    event VotesSubmitted(uint64 indexed epoch, uint256 count);

    /// @notice Emitted for every RP that received a non-zero finalized count when an epoch finalizes.
    /// @dev Raw per-epoch vote data is pruned on finalization, so this event is the canonical
    ///      off-chain record of finalized counts for audit/indexing.
    /// @param epoch The finalized epoch.
    /// @param rpId The Relying Party.
    /// @param count The finalized (lower-median) request count.
    /// @param fee The WLD fee accrued for the RP in this epoch.
    event EpochRpFinalized(uint64 indexed epoch, uint64 indexed rpId, uint64 count, uint256 fee);

    /// @notice Emitted when an RP's outstanding debt is settled.
    /// @param rpId The Relying Party.
    /// @param payer The address that funded the payment.
    /// @param amount The WLD amount transferred to the fee recipient.
    event DebtPaid(uint64 indexed rpId, address indexed payer, uint256 amount);

    /// @notice Emitted when a new tier schedule version is published.
    /// @param version The new (current) schedule version.
    event TierScheduleUpdated(uint32 indexed version);

    /// @notice Emitted when the OPRF key registry address is updated.
    /// @param oldOprfKeyRegistry The previous registry address.
    /// @param newOprfKeyRegistry The new registry address.
    event OprfKeyRegistryUpdated(address oldOprfKeyRegistry, address newOprfKeyRegistry);

    /// @notice Emitted when the epoch timing parameters are updated.
    /// @param epochLength The new epoch length in seconds.
    /// @param votingWindow The new voting window in seconds.
    /// @param paymentWindow The new payment window in seconds.
    event TimingUpdated(uint64 epochLength, uint64 votingWindow, uint64 paymentWindow);

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Submit one or more OPRF node billing votes for a single epoch.
     * @dev Before accepting the votes, opportunistically finalizes a bounded chunk of now-closed
     *      epochs (see {finalizeEpochs}) and prunes their raw vote data. The epoch's node-count and
     *      fee-schedule version are snapshotted on the first accepted vote. Authenticates by
     *      recovered signer, not msg.sender.
     * @param epoch The epoch the votes are cast for; its voting window must be currently open.
     * @param votes The signed votes to record.
     */
    function submitBillingVotes(uint64 epoch, SignedVote[] calldata votes) external;

    /**
     * @notice Settle the full outstanding debt for one or more RPs.
     * @dev Permissionless; finalizes closed epochs first so debt is current. All-or-nothing per RP:
     *      pays the full outstanding debt or reverts if it exceeds the RP's `maxAmount` guard. Pulls
     *      WLD from msg.sender to the fee recipient.
     * @param payments The per-RP payment instructions.
     */
    function pay(RpPayment[] calldata payments) external;

    /**
     * @notice Permissionlessly finalize closed epochs up to (and including) `uptoEpoch`.
     * @dev Flushes the tail when node votes have stopped, so debt and `is_blocked` stay current.
     *      Chunkable: advances the global cursor by at most `maxSteps` units (one per RP finalized,
     *      one per epoch closed), resuming mid-epoch across calls so a large epoch never bricks.
     * @param uptoEpoch The highest epoch to finalize up to; capped at the latest closed epoch.
     * @param maxSteps The maximum units of finalization work to perform in this call.
     */
    function finalizeEpochs(uint64 uptoEpoch, uint256 maxSteps) external;

    /**
     * @notice Publish a new tier schedule version. Existing epochs keep their pinned version.
     * @dev Owner only. Rates must be strictly decreasing, `upTo` strictly ascending, last `upTo`
     *      equal to type(uint256).max.
     * @param tiers The new tier schedule.
     */
    function setTierSchedule(Tier[] calldata tiers) external;

    /**
     * @notice Update the epoch timing parameters.
     * @dev Owner only. Re-checks the `votingWindow <= epochLength` invariant.
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

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Whether an RP is blocked for non-payment.
     * @dev O(1). True when the RP has outstanding finalized debt whose oldest unpaid epoch is past
     *      its payment window. Reflects finalized state only; tail epochs become billable after a
     *      `finalizeEpochs`/`pay`/`submitBillingVotes` call advances finalization.
     * @param rpId The Relying Party.
     * @return Whether the RP is currently blocked.
     */
    function is_blocked(uint64 rpId) external view returns (bool);

    /**
     * @notice The lower-median request count for an RP in a retained (not-yet-finalized) epoch.
     * @dev Finalized epochs are pruned and return 0; their counts are available via {EpochRpFinalized}.
     * @param epoch The epoch.
     * @param rpId The Relying Party.
     * @return The lower-median count, or 0 if below quorum / pruned / unseen.
     */
    function epochRequestCount(uint64 epoch, uint64 rpId) external view returns (uint64);

    /**
     * @notice The current outstanding (finalized) debt for an RP in WLD wei.
     * @param rpId The Relying Party.
     * @return The outstanding debt.
     */
    function outstandingDebt(uint64 rpId) external view returns (uint256);

    /// @notice The EIP-712 domain separator.
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /// @notice The EIP-712 typehash for a billing vote.
    function BILLING_VOTE_TYPEHASH() external view returns (bytes32);
}
