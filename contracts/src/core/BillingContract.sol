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

    /// @dev Packed per-RP rebate-period state. `uint32 + uint224` fills one storage slot.
    struct PeriodState {
        uint32 index;
        uint224 count;
    }

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev OPRF key registry the live node set (n, peer addresses) is read from.
    IOprfNodeSet internal _oprfKeyRegistry;

    /// @dev Append-only history of timing eras; the last entry is the current era. Every epoch
    ///      that ever existed keeps its true boundaries and windows: epoch `e` is governed by the
    ///      newest era with `startEpoch <= e`, so timing changes never affect existing epochs.
    ///      Grows by one entry per {setTiming} call (rare, owner-only), never per epoch.
    TimingEra[] internal _timingEras;

    /// @dev Lowest epoch not yet finalized (global finalization cursor).
    uint32 internal _nextEpochToFinalize;

    /// @dev Number of epochs in a rebate (volume-discount) period.
    uint32 internal _rebatePeriodEpochs;

    /// @dev The single, current ordered tier schedule (no versioning).
    Tier[] internal _tierSchedule;

    /// @dev rpId -> rebate-period index plus requests already billed in that period.
    mapping(uint64 => PeriodState) internal _periodState;

    /// @dev epoch -> rpId -> outstanding finalized debt for that epoch in WLD wei.
    mapping(uint32 => mapping(uint64 => uint256)) internal _epochOwed;

    /// @dev rpId -> finalized epochs with non-zero debt, in ascending finalization order.
    mapping(uint64 => uint32[]) internal _unpaidEpochs;

    /// @dev rpId -> cursor into `_unpaidEpochs[rpId]` for the oldest not-yet-paid epoch.
    mapping(uint64 => uint256) internal _unpaidEpochCursor;

    // --- Transient per-epoch state (pruned when the epoch finalizes) ---

    /// @dev epoch -> signer -> whether the signer already closed its chunked vote.
    mapping(uint32 => mapping(address => bool)) internal _hasVoted;

    /// @dev epoch -> signer -> next chunk index expected from the signer.
    mapping(uint32 => mapping(address => uint32)) internal _nextChunkIndex;

    /// @dev epoch -> signer -> last rpId accepted from the signer, enforcing global ordering.
    mapping(uint32 => mapping(address => uint64)) internal _lastChunkRpId;

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
        // The voting window for `epoch` must be currently open. Window parameters come from the
        // era in which the window opens, so windows of past-era epochs close at their true,
        // historic times regardless of later timing changes.
        uint64 votingStart = epochEnd(epoch);
        if (block.timestamp < votingStart) revert VotingWindowNotOpen();
        if (block.timestamp >= votingStart + _windowEra(epoch).votingWindow) revert VotingWindowClosed();

        uint256 chunkCount = chunks.length;
        for (uint256 i = 0; i < chunkCount; i++) {
            _recordVoteChunk(epoch, chunks[i]);
        }

        emit VoteChunksSubmitted(epoch, chunkCount);
    }

    /// @inheritdoc IBillingContract
    function pay(RpPayment[] calldata payments) external virtual onlyProxy onlyInitialized {
        // Settles currently-finalized debt only. RPs with no selected debt are skipped so a batched, permissionless
        // call is not griefable by debt that was concurrently settled or never accrued.
        uint256 len = payments.length;
        for (uint256 i = 0; i < len; i++) {
            uint64 rpId = payments[i].rpId;
            uint32 uptoEpoch = payments[i].uptoEpoch;
            uint256 amount = _clearDebtThrough(rpId, uptoEpoch);
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
        // that has not started), no epoch is governed by it: update its parameters in place.
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
    function is_blocked(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (bool) {
        uint256 cursor = _unpaidEpochCursor[rpId];
        uint32[] storage epochs = _unpaidEpochs[rpId];
        // No unpaid epochs remain once the cursor reaches the end, so nothing can be overdue.
        // This also guards the indexed read below against an out-of-bounds access.
        if (cursor >= epochs.length) return false;
        return block.timestamp > _paymentDue(epochs[cursor]);
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
        uint32[] storage epochs = _unpaidEpochs[rpId];
        uint256 len = epochs.length;
        for (uint256 cursor = _unpaidEpochCursor[rpId]; cursor < len; cursor++) {
            amount += _epochOwed[epochs[cursor]][rpId];
        }
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

    /// @dev The era governing epoch `epoch`: the newest era with `startEpoch <= epoch`. The walk
    ///      starts at the current era (the common case), and era 0 (`startEpoch == 0`) matches any
    ///      epoch, so the lookup always resolves.
    function _eraOf(uint256 epoch) internal view returns (TimingEra storage) {
        uint256 i = _timingEras.length - 1;
        while (i > 0 && epoch < _timingEras[i].startEpoch) {
            unchecked {
                i--;
            }
        }
        return _timingEras[i];
    }

    /// @dev The era an epoch's voting window (and payment window) is governed by. An era's
    ///      parameters govern its timespan, and the window opens at `epochEnd(epoch)` — the start
    ///      of epoch `epoch + 1` — so it is governed by that epoch's era. This keeps window
    ///      closes monotone in epoch number across era changes (given the per-era
    ///      `votingWindow <= epochLength` invariant), which {_latestClosedEpoch} and sequential
    ///      finalization rely on. See {IBillingContract.TimingEra} for a worked example.
    function _windowEra(uint32 epoch) internal view returns (TimingEra storage) {
        return _eraOf(uint256(epoch) + 1);
    }

    /// @dev The payment-due timestamp for `epoch`: end of its voting window plus the payment
    ///      window, both from the epoch's own window era — historic deadlines never move when
    ///      timing parameters change.
    function _paymentDue(uint32 epoch) internal view returns (uint64) {
        TimingEra storage era = _windowEra(epoch);
        return epochEnd(epoch) + era.votingWindow + era.paymentWindow;
    }

    /// @dev Clears `rp`'s finalized debt through `uptoEpoch`, then advances its unpaid-epoch cursor.
    function _clearDebtThrough(uint64 rp, uint32 uptoEpoch) internal returns (uint256 amount) {
        uint256 cursor = _unpaidEpochCursor[rp];

        while (cursor < _unpaidEpochs[rp].length) {
            uint32 epoch = _unpaidEpochs[rp][cursor];
            if (epoch > uptoEpoch) break;

            uint256 debt = _epochOwed[epoch][rp];
            if (debt != 0) {
                amount += debt;
                delete _epochOwed[epoch][rp];
            }

            delete _unpaidEpochs[rp][cursor];

            unchecked {
                cursor++;
            }
        }

        // The cursor advances monotonically and is never reset: paid slots are already zeroed
        // above, so live storage stays bounded by the outstanding backlog without an O(n) array
        // delete on the clearing payment. When fully paid, `cursor == _unpaidEpochs[rp].length`,
        // which `is_blocked` and `outstandingDebt` treat as "no outstanding debt".
        _unpaidEpochCursor[rp] = cursor;
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

    /// @dev Whether `signer` has submitted any chunk for `epoch`.
    function _isSubmitter(uint32 epoch, address signer) internal view returns (bool) {
        address[] storage submitters = _epochSubmitters[epoch];
        uint256 submitterCount = submitters.length;
        for (uint256 i = 0; i < submitterCount; i++) {
            if (submitters[i] == signer) return true;
        }
        return false;
    }

    /// @dev Prunes epoch-level transient state after all queued RPs for `epoch` are finalized.
    function _pruneFinalizedEpoch(uint32 epoch) internal {
        address[] storage submitters = _epochSubmitters[epoch];
        uint256 submitterCount = submitters.length;
        for (uint256 i = 0; i < submitterCount; i++) {
            address signer = submitters[i];
            delete _hasVoted[epoch][signer];
            delete _nextChunkIndex[epoch][signer];
            delete _lastChunkRpId[epoch][signer];
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
            _epochOwed[epoch][rp] = fee;
            _unpaidEpochs[rp].push(epoch);
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
        PeriodState storage period = _periodState[rp];
        if (period.index != periodIdx) {
            period.index = periodIdx;
            period.count = 0;
        }

        // Return the previous period count
        base = period.count;
        uint256 newPeriodCount = base + epoch_count;
        if (newPeriodCount > type(uint224).max) revert PeriodStateOverflow();
        period.count = uint224(newPeriodCount);
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
        if (_hasVoted[epoch][signer]) revert VoteAlreadyClosed();

        uint32 expectedChunkIndex = _nextChunkIndex[epoch][signer];
        if (chunk.chunkIndex != expectedChunkIndex) revert UnexpectedChunkIndex();
        // Check if RP id is ascending
        uint64 previousRpId = _lastChunkRpId[epoch][signer];
        if (chunk.counts.length != 0) {
            uint64 firstRpId = chunk.counts[0].rpId;
            if (firstRpId <= previousRpId) revert CountsNotAscending();
            _lastChunkRpId[epoch][signer] = lastRpId;
        }
        // Push signer to submitters if this is their first chunk for the epoch
        if (!_isSubmitter(epoch, signer)) {
            _epochSubmitters[epoch].push(signer);
        }
        _nextChunkIndex[epoch][signer] = expectedChunkIndex + 1;
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
            _hasVoted[epoch][signer] = true;
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
