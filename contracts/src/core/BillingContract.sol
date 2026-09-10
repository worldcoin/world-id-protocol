// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {WorldIDBase} from "./abstract/WorldIDBase.sol";
import {IBillingContract} from "./interfaces/IBillingContract.sol";

/**
 * @notice Minimal view of the OPRF key registry: the live node set the Billing Contract
 *         authenticates votes against. Both members are public state variables on the deployed
 *         `OprfKeyRegistry`, so their auto-generated getters satisfy this interface.
 */
interface IOprfNodeSet {
    /// @notice The number of OPRF peers participating in key generation.
    function numPeers() external view returns (uint16);

    /// @notice The OPRF peer address at `index` (0 <= index < numPeers()).
    function peerAddresses(uint256 index) external view returns (address);
}

/**
 * @title BillingContract (World ID)
 * @author World Contributors
 * @notice World ID. On-chain billing for Uniqueness Proofs per WIP-107.
 * @dev OPRF nodes count unique RP requests per epoch and submit EIP-712-signed vote chunks. The contract
 *      finalizes the lower-median count across the node set (gated on quorum), prices it through a
 *      tiered WLD fee schedule, accrues per-RP debt, and blocks RPs past their payment window.
 *      Finalization is permissionless and chunkable ({finalizeEpochs}), and must be driven by a third party.
 *
 * @custom:repo https://github.com/worldcoin/world-id-protocol
 */
contract BillingContract is WorldIDBase, IBillingContract {
    using SafeERC20 for IERC20;

    ////////////////////////////////////////////////////////////
    //                        Structs                         //
    ////////////////////////////////////////////////////////////

    /// @dev One finalized epoch with outstanding debt. `uint32 + uint224` fills one storage slot.
    struct UnpaidEpoch {
        uint32 epoch;
        uint224 amount;
    }

    /// @dev All per-RP billing state. `periodIndex + periodCount` pack into one storage slot.
    struct RpState {
        // rebate-period index the running count belongs to.
        uint32 periodIndex;
        // requests already billed in that rebate period.
        uint224 periodCount;
        // cursor into `unpaidEpochs` for the oldest not-yet-paid epoch.
        uint64 unpaidCursor;
        // finalized epochs with non-zero debt, in ascending finalization order.
        UnpaidEpoch[] unpaidEpochs;
    }

    /// @dev Per-(epoch, signer) chunked-vote progress. Packed into one storage slot.
    struct SubmitterState {
        // next chunk index expected from the signer; non-zero iff the signer has submitted.
        uint32 nextChunkIndex;
        // last rpId accepted from the signer, enforcing global ordering across chunks.
        uint64 lastChunkRpId;
        // whether the signer already closed its chunked vote.
        bool hasVoted;
    }

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev OPRF key registry the live node set (n, peer addresses) is read from.
    IOprfNodeSet internal _oprfKeyRegistry;

    /// @dev Append-only history of timing eras; the last entry is the current era.
    TimingEra[] internal _timingEras;

    /// @dev Lowest epoch not yet finalized (global finalization cursor).
    uint32 internal _nextEpochToFinalize;

    /// @dev Number of epochs in a rebate (volume-discount) period.
    uint32 internal _rebatePeriodEpochs;

    /// @dev The single, current ordered tier schedule (no versioning).
    Tier[] internal _tierSchedule;

    /// @dev rpId -> all per-RP billing state (rebate period, unpaid-epoch debt list and cursor).
    mapping(uint64 => RpState) internal _rpState;

    // --- Transient per-epoch state (pruned when the epoch finalizes) ---

    /// @dev epoch -> signer -> chunked-vote progress (chunk cursor, rpId ordering, voted flag).
    mapping(uint32 => mapping(address => SubmitterState)) internal _submitterState;

    /// @dev epoch -> all signers that submitted at least one chunk, completed or not.
    mapping(uint32 => address[]) internal _epochSubmitters;

    /// @dev epoch -> signers whose chunked votes are complete and count toward quorum/medians.
    mapping(uint32 => address[]) internal _epochVoters;

    /// @dev epoch -> rpIds that received at least one non-zero count and need finalization.
    mapping(uint32 => uint64[]) internal _epochRpsToFinalize;

    /// @dev epoch -> rpId -> whether the rp is already in `_epochRpsToFinalize[epoch]`.
    mapping(uint32 => mapping(uint64 => bool)) internal _epochRpsToFinalizeSet;

    /// @dev epoch -> signer -> rpId -> the non-zero count submitted by the signer for the rp.
    mapping(uint32 => mapping(address => mapping(uint64 => uint64))) internal _epochVoteCounts;

    /// @dev Index into `_epochRpsToFinalize[_nextEpochToFinalize]` of the next RP to finalize, so a
    ///      single oversized epoch can be finalized across multiple (chunked) calls.
    uint256 internal _finalizeRpCursor;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "BillingContract";
    string public constant EIP712_VERSION = "1.0";

    /// @inheritdoc IBillingContract
    bytes32 public constant BILLING_VOTE_CHUNK_TYPEHASH = keccak256(
        "BillingVoteChunk(uint32 epoch,uint32 chunkIndex,bool isFinal,RpCount[] counts)RpCount(uint64 rpId,uint64 count)"
    );

    /// @dev EIP-712 typehash for a single RpCount struct (member of a BillingVoteChunk).
    bytes32 public constant RPCOUNT_TYPEHASH = keccak256("RpCount(uint64 rpId,uint64 count)");

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    ////////////////////////////////////////////////////////////
    //                      Initializer                       //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Initializes the contract.
     * @param feeRecipient The recipient of collected WLD fees.
     * @param feeToken The WLD ERC-20 token used for fee payments.
     * @param oprfKeyRegistry The OPRF key registry the node set is read from.
     * @param genesis Unix timestamp of epoch 0's start.
     * @param epochLength Epoch length in seconds.
     * @param votingWindow Voting window in seconds (must be <= epochLength).
     * @param paymentWindow Payment window in seconds.
     * @param tiers Initial fee schedule (stored as version 0).
     * @param rebatePeriodEpochs Number of epochs per rebate period.
     */
    function initialize(
        address feeRecipient,
        address feeToken,
        address oprfKeyRegistry,
        uint64 genesis,
        uint64 epochLength,
        uint64 votingWindow,
        uint64 paymentWindow,
        Tier[] calldata tiers,
        uint32 rebatePeriodEpochs
    ) public virtual initializer {
        if (oprfKeyRegistry == address(0) || feeToken == address(0) || feeRecipient == address(0)) {
            revert ZeroAddress();
        }

        // registrationFee is unused (0); _feeToken (WLD) and _feeRecipient are reused for payments.
        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, feeRecipient, feeToken, 0);

        _oprfKeyRegistry = IOprfNodeSet(oprfKeyRegistry);
        // We require voting window to be less than epoch length to prevent overlapping voting windows.
        if (epochLength == 0 || votingWindow == 0 || paymentWindow == 0 || votingWindow > epochLength) {
            revert InvalidTiming();
        }
        if (rebatePeriodEpochs == 0) revert InvalidTiming();

        _timingEras.push(
            TimingEra({
                startEpoch: 0,
                startTime: genesis,
                epochLength: epochLength,
                votingWindow: votingWindow,
                paymentWindow: paymentWindow
            })
        );
        _rebatePeriodEpochs = rebatePeriodEpochs;

        _validateTiers(tiers);
        _storeTierSchedule(tiers);
        emit TierScheduleUpdated();
    }

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBillingContract
    function submitBillingVotes(uint32 epoch, SignedVoteChunk[] calldata chunks)
        external
        virtual
        onlyProxy
        onlyInitialized
    {
        // The voting window for `epoch` must be currently open.
        uint64 votingStart = epochEnd(epoch);
        if (block.timestamp < votingStart) revert VotingWindowNotOpen();
        if (block.timestamp >= votingStart + _votingWindowEraOf(epoch).votingWindow) revert VotingWindowClosed();

        uint256 chunkCount = chunks.length;
        for (uint256 i = 0; i < chunkCount; i++) {
            _recordVoteChunk(epoch, chunks[i]);
        }
    }

    /// @inheritdoc IBillingContract
    function pay(RpPayment[] calldata payments) external virtual onlyProxy onlyInitialized {
        // Settles currently-finalized debt only. RPs with no selected debt are skipped so a batched, permissionless
        // call is not griefable by debt that was concurrently settled or never accrued.
        uint256 len = payments.length;
        for (uint256 i = 0; i < len; i++) {
            uint64 rpId = payments[i].rpId;
            uint32 uptoEpoch = payments[i].uptoEpoch;
            uint256 amount = _clearDebtUpToEpoch(rpId, uptoEpoch);
            if (amount == 0) continue;
            if (amount > payments[i].maxAmount) revert DebtExceedsMax();

            // Effects happen in {_clearDebtThrough}; pull tokens after state is updated.
            _feeToken.safeTransferFrom(msg.sender, _feeRecipient, amount);

            emit DebtPaid(rpId, msg.sender, uptoEpoch, amount);
        }
    }

    /// @inheritdoc IBillingContract
    function finalizeEpochs(uint32 uptoEpoch, uint256 maxSteps) external virtual onlyProxy onlyInitialized {
        (bool exists, uint32 closed) = _latestClosedEpoch();
        if (!exists) return;
        uint32 target = uptoEpoch < closed ? uptoEpoch : closed;

        uint32 e = _nextEpochToFinalize;
        uint256 cursor = _finalizeRpCursor;
        // Steps are either a single finalizeRp call or a pruneFinalizedEpoch call
        uint256 steps = 0;

        while (e <= target && steps < maxSteps) {
            uint64[] storage rps = _epochRpsToFinalize[e];
            uint256 len = rps.length;

            while (cursor < len && steps < maxSteps) {
                _finalizeRp(e, rps[cursor]);
                unchecked {
                    cursor++;
                    steps++;
                }
            }
            // Only prune if we haven't exhausted the step budget
            if (steps < maxSteps) {
                _pruneFinalizedEpoch(e);
                cursor = 0;
                e++;
                unchecked {
                    steps++;
                }
            }
        }

        _nextEpochToFinalize = e;
        _finalizeRpCursor = cursor;
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBillingContract
    function setTierSchedule(Tier[] calldata tiers) external virtual onlyOwner onlyProxy onlyInitialized {
        _validateTiers(tiers);
        _storeTierSchedule(tiers);
        emit TierScheduleUpdated();
    }

    /// @inheritdoc IBillingContract
    function setTiming(uint64 epochLength, uint64 votingWindow, uint64 paymentWindow)
        external
        virtual
        onlyOwner
        onlyProxy
        onlyInitialized
    {
        if (epochLength == 0 || votingWindow == 0 || paymentWindow == 0 || votingWindow > epochLength) {
            revert InvalidTiming();
        }

        TimingEra storage current = _timingEras[_timingEras.length - 1];

        // If the current era has not started yet (repeated change within one epoch, or a genesis
        // that has not started), update its parameters in place.
        if (block.timestamp < current.startTime) {
            current.epochLength = epochLength;
            current.votingWindow = votingWindow;
            current.paymentWindow = paymentWindow;
            emit TimingUpdated(epochLength, votingWindow, paymentWindow, current.startEpoch, current.startTime);
            return;
        }

        // Otherwise append a new era starting after the in-flight epoch. Existing epochs are
        // never affected: their boundaries, voting windows, and payment deadlines stay defined
        // by the eras they belong to; the new parameters govern later epochs only.
        uint64 d = uint64(block.timestamp) - current.startTime;
        uint256 eCur = uint256(current.startEpoch) + d / current.epochLength; // the in-flight epoch
        if (eCur + 1 > type(uint32).max) revert EpochTooLarge();
        uint64 startTime = epochEnd(uint32(eCur));

        _timingEras.push(
            TimingEra({
                startEpoch: uint32(eCur) + 1,
                startTime: startTime,
                epochLength: epochLength,
                votingWindow: votingWindow,
                paymentWindow: paymentWindow
            })
        );
        emit TimingUpdated(epochLength, votingWindow, paymentWindow, uint32(eCur) + 1, startTime);
    }

    /// @inheritdoc IBillingContract
    function updateOprfKeyRegistry(address newOprfKeyRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newOprfKeyRegistry == address(0)) revert ZeroAddress();
        address oldOprfKeyRegistry = address(_oprfKeyRegistry);
        _oprfKeyRegistry = IOprfNodeSet(newOprfKeyRegistry);
        emit OprfKeyRegistryUpdated(oldOprfKeyRegistry, newOprfKeyRegistry);
    }

    /// @inheritdoc IBillingContract
    function setRebatePeriodEpochs(uint32 rebatePeriodEpochs) external virtual onlyOwner onlyProxy onlyInitialized {
        if (rebatePeriodEpochs == 0) revert InvalidTiming();
        _rebatePeriodEpochs = rebatePeriodEpochs;
        emit RebatePeriodUpdated(rebatePeriodEpochs);
    }

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBillingContract
    function isBlocked(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (bool) {
        RpState storage state = _rpState[rpId];
        uint256 cursor = state.unpaidCursor;
        UnpaidEpoch[] storage unpaid = state.unpaidEpochs;
        // No unpaid epochs remain once the cursor reaches the end, so nothing can be overdue.
        // This also guards the indexed read below against an out-of-bounds access.
        if (cursor >= unpaid.length) return false;
        return block.timestamp > _paymentDue(unpaid[cursor].epoch);
    }

    /// @inheritdoc IBillingContract
    function epochRequestCount(uint32 epoch, uint64 rpId)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint64)
    {
        // Returns 0 for finalized (pruned) epochs, since their snapshot/counts are deleted.
        return _median(epoch, rpId);
    }

    /// @inheritdoc IBillingContract
    function outstandingDebt(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (uint256 amount) {
        RpState storage state = _rpState[rpId];
        UnpaidEpoch[] storage unpaid = state.unpaidEpochs;
        uint256 len = unpaid.length;
        for (uint256 cursor = state.unpaidCursor; cursor < len; cursor++) {
            amount += unpaid[cursor].amount;
        }
    }

    /// @inheritdoc IBillingContract
    function epochWatermarks()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bool finalizedExists, uint32 finalizedEpoch, bool closedExists, uint32 closedEpoch)
    {
        uint32 next = _nextEpochToFinalize;
        if (next != 0) {
            finalizedExists = true;
            finalizedEpoch = next - 1;
        }
        (closedExists, closedEpoch) = _latestClosedEpoch();
    }

    /// @inheritdoc IBillingContract
    function DOMAIN_SEPARATOR() external view virtual onlyProxy onlyInitialized returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice The timestamp at which epoch `epoch` ends (and its voting window opens).
    /// @dev Defined for every epoch, past or future: the boundary derives from the era the epoch
    ///      belongs to, so timing changes never move it.
    function epochEnd(uint32 epoch) public view virtual returns (uint64) {
        TimingEra storage era = _eraOf(epoch);
        uint256 end = uint256(era.startTime) + (uint256(epoch) + 1 - era.startEpoch) * era.epochLength;
        if (end > type(uint64).max) revert EpochTooLarge();
        return uint64(end);
    }

    /// @notice The timestamp at which epoch `epoch`'s voting window closes.
    /// @dev Voting is open over `[epochEnd(epoch), votingWindowEnd(epoch))`. The window size is
    ///      governed by the era of epoch `epoch + 1` (see {_votingWindowEraOf}), so this stays exact
    ///      across timing changes rather than relying on the current era.
    function votingWindowEnd(uint32 epoch) public view virtual returns (uint64) {
        return epochEnd(epoch) + _votingWindowEraOf(epoch).votingWindow;
    }

    /// @notice The timestamp at which epoch `epoch`'s payment window closes; payment is overdue after it.
    /// @dev End of the voting window plus the payment window, both governed by the era of epoch `epoch + 1`.
    function paymentWindowEnd(uint32 epoch) public view virtual returns (uint64) {
        return _paymentDue(epoch);
    }

    /// @notice The OPRF key registry address the node set is read from.
    function getOprfKeyRegistry() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_oprfKeyRegistry);
    }

    /// @inheritdoc IBillingContract
    function getTierSchedule() external view virtual onlyProxy onlyInitialized returns (Tier[] memory) {
        return _tierSchedule;
    }

    /// @inheritdoc IBillingContract
    function getRebatePeriodEpochs() external view virtual onlyProxy onlyInitialized returns (uint32) {
        return _rebatePeriodEpochs;
    }

    /// @inheritdoc IBillingContract
    function getTiming()
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (
            uint64 epochLength,
            uint64 votingWindow,
            uint64 paymentWindow,
            uint32 eraStartEpoch,
            uint64 eraStartTime
        )
    {
        TimingEra storage era = _timingEras[_timingEras.length - 1];
        return (era.epochLength, era.votingWindow, era.paymentWindow, era.startEpoch, era.startTime);
    }

    /// @inheritdoc IBillingContract
    function getEras() external view virtual onlyProxy onlyInitialized returns (TimingEra[] memory) {
        return _timingEras;
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /// @dev The TimingEra governing epoch `epoch`: the newest era with `startEpoch <= epoch`. The walk
    ///      starts at the current era (the common case), and era 0 (`startEpoch == 0`) matches any
    ///      epoch, so the lookup always resolves.
    function _eraOf(uint32 epoch) internal view returns (TimingEra storage) {
        uint256 i = _timingEras.length - 1;
        while (i > 0 && epoch < _timingEras[i].startEpoch) {
            unchecked {
                i--;
            }
        }
        return _timingEras[i];
    }

    /// @dev The TimingEra an epoch's voting window (and payment window) is governed by.
    //       On the last epoch of an era, the size of the voting window is governed by the next era to prevent overlapping voting windows.
    function _votingWindowEraOf(uint32 epoch) internal view returns (TimingEra storage) {
        return _eraOf(epoch + 1);
    }

    /// @dev The payment-due timestamp for `epoch`: end of its voting window plus the payment window from the voting window era.
    function _paymentDue(uint32 epoch) internal view returns (uint64) {
        TimingEra storage era = _votingWindowEraOf(epoch);
        return epochEnd(epoch) + era.votingWindow + era.paymentWindow;
    }

    /// @dev Clears `rp`'s finalized debt through `uptoEpoch`, then advances its unpaid-epoch cursor.
    function _clearDebtUpToEpoch(uint64 rp, uint32 uptoEpoch) internal returns (uint256 amount) {
        RpState storage state = _rpState[rp];
        UnpaidEpoch[] storage unpaid = state.unpaidEpochs;
        uint256 cursor = state.unpaidCursor;

        while (cursor < unpaid.length) {
            UnpaidEpoch storage entry = unpaid[cursor];
            uint32 epoch = entry.epoch;
            if (epoch > uptoEpoch) break;

            amount += entry.amount;
            delete unpaid[cursor];

            unchecked {
                cursor++;
            }
        }

        // The cursor advances monotonically and is never reset: paid slots are already zeroed
        // above, so live storage stays bounded by the outstanding backlog without an O(n) array
        // delete on the clearing payment. When fully paid, `cursor == unpaidEpochs.length`,
        // which `isBlocked` and `outstandingDebt` treat as "no outstanding debt".
        state.unpaidCursor = uint64(cursor);
    }

    /// @dev The latest epoch whose voting window has fully closed, if any — exact across eras.
    ///      An era's window regime covers epochs `startEpoch - 1` through `nextEra.startEpoch - 2`,
    ///      closing at `startTime + k * epochLength + votingWindow`. The walk finds the newest era
    ///      whose first close has passed; the result is capped at the era's own regime, since the
    ///      next regime's first window may still be open. All windows of older regimes close by
    ///      their regime's end (`votingWindow <= epochLength`), so everything below is closed too.
    function _latestClosedEpoch() internal view returns (bool exists, uint32 epoch) {
        uint256 i = _timingEras.length;
        while (i > 0) {
            unchecked {
                i--;
            }
            TimingEra storage era = _timingEras[i];
            uint256 firstClose = uint256(era.startTime) + era.votingWindow;
            if (block.timestamp < firstClose) continue; // no window of this regime has closed yet

            uint256 k = (block.timestamp - firstClose) / era.epochLength;
            // The largest closed epoch of this regime is `startEpoch + k - 1`.
            uint256 latestPlusOne = uint256(era.startEpoch) + k;
            if (i + 1 < _timingEras.length) {
                uint256 regimeEndPlusOne = _timingEras[i + 1].startEpoch - 1;
                if (latestPlusOne > regimeEndPlusOne) latestPlusOne = regimeEndPlusOne;
            }
            if (latestPlusOne == 0) return (false, 0); // fresh deployment: epoch 0 has not closed yet
            if (latestPlusOne - 1 > type(uint32).max) revert EpochTooLarge();
            return (true, uint32(latestPlusOne - 1));
        }
        return (false, 0);
    }

    /// @dev The billing quorum for a node set of size `n`: a strict majority, floor(n/2)+1.
    function _quorum(uint16 n) internal pure returns (uint16) {
        return n / 2 + 1;
    }

    /// @dev Whether `who` is a member of the live OPRF node set.
    function _isNode(address who) internal view returns (bool) {
        uint16 n = _oprfKeyRegistry.numPeers();
        for (uint256 i = 0; i < n; i++) {
            if (_oprfKeyRegistry.peerAddresses(i) == who) return true;
        }
        return false;
    }

    /// @dev Prunes epoch-level transient state after all queued RPs for `epoch` are finalized.
    function _pruneFinalizedEpoch(uint32 epoch) internal {
        address[] storage submitters = _epochSubmitters[epoch];
        uint256 submitterCount = submitters.length;
        for (uint256 i = 0; i < submitterCount; i++) {
            delete _submitterState[epoch][submitters[i]];
        }
        delete _epochSubmitters[epoch];
        delete _epochVoters[epoch];
        delete _epochRpsToFinalize[epoch];
    }

    /// @dev Finalizes a single (epoch, rp): prices its lower-median count through the current
    ///      schedule, accrues debt, emits the audit event, and prunes the raw counts.
    function _finalizeRp(uint32 epoch, uint64 rp) internal {
        uint64 median_count = _median(epoch, rp);
        // Prune counts for all submitters; deleting a missing rp count keeps default zero
        address[] storage submitters = _epochSubmitters[epoch];
        uint256 submitterCount = submitters.length;
        for (uint256 i = 0; i < submitterCount; i++) {
            delete _epochVoteCounts[epoch][submitters[i]][rp];
        }
        delete _epochRpsToFinalizeSet[epoch][rp]; // prune finalization queue membership

        if (median_count == 0) return; // below quorum or zero median nothing billed, no event

        uint256 base = _updatePeriodCountAndReturnBase(rp, epoch, median_count);
        uint256 fee = _calculateTieredFee(base, median_count);

        if (fee > 0) {
            if (fee > type(uint224).max) revert FeeOverflow();
            _rpState[rp].unpaidEpochs.push(UnpaidEpoch({epoch: epoch, amount: uint224(fee)}));
        }

        emit EpochRpFinalized(epoch, rp, median_count, fee);
    }

    /// @dev Updates an RP's running rebate-period count and returns the count before this epoch.
    function _updatePeriodCountAndReturnBase(uint64 rp, uint32 epoch, uint64 epoch_count)
        internal
        returns (uint256 base)
    {
        // Check if the epoch is a new period boundary and reset the period count if so
        uint32 periodIdx = epoch / _rebatePeriodEpochs;
        RpState storage state = _rpState[rp];
        if (state.periodIndex != periodIdx) {
            state.periodIndex = periodIdx;
            state.periodCount = 0;
        }

        // Return the previous period count
        base = state.periodCount;
        uint256 newPeriodCount = base + epoch_count;
        if (newPeriodCount > type(uint224).max) revert PeriodStateOverflow();
        state.periodCount = uint224(newPeriodCount);
    }

    /// @dev The lower median of an RP's submitted counts for `epoch`, with missing votes counted as
    ///      zero over the epoch's voters, gated on quorum. Returns 0 below quorum or for pruned/unvoted epochs.
    function _median(uint32 epoch, uint64 rp) internal view returns (uint64) {
        address[] storage voters = _epochVoters[epoch];
        uint256 voterCount = voters.length;
        if (voterCount == 0) return 0; // no votes (or pruned)

        // Quorum is read live from the current node set.
        uint16 n = _oprfKeyRegistry.numPeers();
        if (voterCount < _quorum(n)) return 0;

        uint64[] memory vals = new uint64[](voterCount);
        for (uint256 i = 0; i < voterCount; i++) {
            // Missing rp reports read as the mapping default zero and count in the median.
            uint64 count = _epochVoteCounts[epoch][voters[i]][rp];

            uint256 j = i;
            while (j > 0 && count < vals[j - 1]) {
                vals[j] = vals[j - 1];
                unchecked {
                    j--;
                }
            }
            vals[j] = count;
        }

        // Lower-median index over the v values (0-indexed).
        return vals[(voterCount - 1) / 2];
    }

    /// @dev The marginal WLD fee for billing `count` additional requests on top of `base` already
    ///      billed this rebate period, using the current tier schedule (WIP-107 §6.4 tiered pricing).
    function _calculateTieredFee(uint256 base, uint256 count) internal view returns (uint256 fee) {
        Tier[] storage tiers = _tierSchedule;
        uint256 from = base;
        uint256 to = base + count;
        uint256 len = tiers.length;
        for (uint256 i = 0; i < len && from < to; i++) {
            // Note: For the last tier, upTo is type(uint256).max
            uint256 boundary = tiers[i].upTo;
            if (boundary <= from) continue; // tier already fully consumed by `base`
            uint256 segEnd = boundary < to ? boundary : to;
            fee += (segEnd - from) * tiers[i].rate;
            from = segEnd;
        }
    }

    /// @dev Validates, authenticates and records a single node's vote chunk for `epoch`.
    function _recordVoteChunk(uint32 epoch, SignedVoteChunk calldata chunk) internal {
        // Validate the counts (strictly ascending rpId, all non-zero) and build the EIP-712
        // hash of the RpCount[] array in a single pass
        (bytes32 countsHash, uint64 lastRpId) = _validateAndHashCounts(chunk.counts);
        // Authenticate by recovered signer, not msg.sender — any party may relay the votes
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(BILLING_VOTE_CHUNK_TYPEHASH, epoch, chunk.chunkIndex, chunk.isFinal, countsHash))
        );
        address signer = ECDSA.recover(digest, chunk.signature);

        if (!_isNode(signer)) revert NotANode();

        SubmitterState storage sub = _submitterState[epoch][signer];
        if (sub.hasVoted) revert VoteAlreadyClosed();

        uint32 expectedChunkIndex = sub.nextChunkIndex;
        if (chunk.chunkIndex != expectedChunkIndex) revert UnexpectedChunkIndex();
        // Check if RP id is ascending
        if (chunk.counts.length != 0) {
            uint64 firstRpId = chunk.counts[0].rpId;
            if (firstRpId <= sub.lastChunkRpId) revert CountsNotAscending();
            sub.lastChunkRpId = lastRpId;
        }
        // A zero chunk cursor means this is the signer's first chunk for the epoch
        if (expectedChunkIndex == 0) {
            _epochSubmitters[epoch].push(signer);
        }
        sub.nextChunkIndex = expectedChunkIndex + 1;
        // Update vote counts for each RP in the chunk
        uint256 len = chunk.counts.length;
        for (uint256 i = 0; i < len; i++) {
            uint64 rpId = chunk.counts[i].rpId;
            // Queue RP for finalization if this is the first non-zero count seen for this rp in the epoch
            if (!_epochRpsToFinalizeSet[epoch][rpId]) {
                _epochRpsToFinalizeSet[epoch][rpId] = true;
                _epochRpsToFinalize[epoch].push(rpId);
            }
            _epochVoteCounts[epoch][signer][rpId] = chunk.counts[i].count;
        }
        // If this is the final chunk for the epoch, mark the signer as voted
        if (chunk.isFinal) {
            sub.hasVoted = true;
            _epochVoters[epoch].push(signer);
        }
    }

    /// @dev Validates a vote's counts and returns the EIP-712 hash of the RpCount[] array.
    ///      rpIds must be strictly ascending (rejects duplicates and the invalid rpId 0); counts
    ///      must all be non-zero (zero counts are implicit and must be omitted).
    function _validateAndHashCounts(RpCount[] calldata counts) internal pure returns (bytes32, uint64 lastRpId) {
        uint256 len = counts.length;
        bytes32[] memory hashes = new bytes32[](len);
        uint64 prevRpId = 0;
        for (uint256 i = 0; i < len; i++) {
            uint64 rpId = counts[i].rpId;
            uint64 count = counts[i].count;
            if (count == 0) revert ZeroCount();
            if (rpId <= prevRpId) revert CountsNotAscending();
            prevRpId = rpId;
            hashes[i] = keccak256(abi.encode(RPCOUNT_TYPEHASH, rpId, count));
        }
        return (keccak256(abi.encodePacked(hashes)), prevRpId);
    }

    /// @dev Validates a tier schedule: non-empty, strictly ascending `upTo` ending at max,
    ///      strictly decreasing rates.
    function _validateTiers(Tier[] calldata tiers) internal pure {
        uint256 len = tiers.length;
        if (len == 0) revert InvalidTierSchedule();
        for (uint256 i = 0; i < len; i++) {
            if (i > 0) {
                // strictly ascending boundaries, strictly decreasing rates.
                if (tiers[i].upTo <= tiers[i - 1].upTo) revert InvalidTierSchedule();
                if (tiers[i].rate >= tiers[i - 1].rate) revert InvalidTierSchedule();
            }
        }
        if (tiers[len - 1].upTo != type(uint256).max) revert InvalidTierSchedule();
    }

    /// @dev Replaces the current tier schedule with a validated one.
    function _storeTierSchedule(Tier[] calldata tiers) internal {
        delete _tierSchedule; // clear any existing schedule before repopulating
        uint256 len = tiers.length;
        for (uint256 i = 0; i < len; i++) {
            _tierSchedule.push(tiers[i]);
        }
    }
}
