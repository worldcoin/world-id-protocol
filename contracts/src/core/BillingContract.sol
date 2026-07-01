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
 * @dev OPRF nodes count unique RP requests per epoch and submit EIP-712-signed votes. The contract
 *      finalizes the lower-median count across the node set (gated on quorum), prices it through a
 *      tiered WLD fee schedule, accrues per-RP debt, and blocks RPs past their payment window.
 *      Finalization is permissionless and chunkable ({finalizeEpochs}) — it is the sole driver, so
 *      a keeper must run it (cadence < paymentWindow keeps {is_blocked} never-late). Neither
 *      {submitBillingVotes} nor {pay} finalize as a side effect, keeping their gas predictable.
 *      Finalizing prunes raw vote data, so raw state scales with participants, not time, and no
 *      single call can be bricked by an oversized epoch.
 * @custom:repo https://github.com/worldcoin/world-id-protocol
 */
contract BillingContract is WorldIDBase, IBillingContract {
    using SafeERC20 for IERC20;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev OPRF key registry the live node set (n, peer addresses) is read from.
    IOprfNodeSet internal _oprfKeyRegistry;

    /// @dev Unix timestamp of epoch 0's start. Epoch boundaries derive from this.
    uint64 internal _genesis;

    /// @dev Length of one epoch in seconds.
    uint64 internal _epochLength;

    /// @dev Seconds after an epoch ends during which nodes may submit votes for it.
    uint64 internal _votingWindow;

    /// @dev Seconds after voting closes during which an RP must pay before it is blocked.
    uint64 internal _paymentWindow;

    /// @dev Lowest epoch not yet finalized (global finalization cursor).
    uint64 internal _nextEpochToFinalize;

    /// @dev Number of epochs in a rebate (volume-discount) period.
    uint64 internal _rebatePeriodEpochs;

    /// @dev Current (latest) fee-schedule version. New epochs pin this on their first vote.
    uint32 internal _currentScheduleVersion;

    /// @dev version -> ordered tier schedule.
    mapping(uint32 => Tier[]) internal _tierSchedules;

    /// @dev rpId -> requests already billed in the RP's current rebate period.
    mapping(uint64 => uint256) internal _periodCount;

    /// @dev rpId -> the rebate-period index `_periodCount` is scoped to.
    mapping(uint64 => uint64) internal _periodIndex;

    /// @dev rpId -> outstanding finalized debt in WLD wei.
    mapping(uint64 => uint256) internal _totalOwed;

    /// @dev rpId -> payment-due timestamp of the oldest unpaid billable epoch (0 when debt-free).
    mapping(uint64 => uint64) internal _oldestUnpaidDue;

    // --- Transient per-epoch state (pruned when the epoch finalizes) ---

    /// @dev epoch -> signer -> whether the signer already voted.
    mapping(uint64 => mapping(address => bool)) internal _hasVoted;

    /// @dev epoch -> number of distinct nodes that voted (V).
    mapping(uint64 => uint64) internal _epochVoterCount;

    /// @dev epoch -> node count snapshot taken on the epoch's first vote.
    mapping(uint64 => uint16) internal _nSnapshot;

    /// @dev epoch -> fee-schedule version pinned on the epoch's first vote.
    mapping(uint64 => uint32) internal _scheduleVersion;

    /// @dev epoch -> rpIds that received at least one non-zero count.
    mapping(uint64 => uint64[]) internal _epochRpList;

    /// @dev epoch -> rpId -> the non-zero counts submitted for it.
    mapping(uint64 => mapping(uint64 => uint64[])) internal _epochRpCounts;

    /// @dev Index into `_epochRpList[_nextEpochToFinalize]` of the next RP to finalize, so a
    ///      single oversized epoch can be finalized across multiple (chunked) calls.
    uint256 internal _finalizeRpCursor;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "BillingContract";
    string public constant EIP712_VERSION = "1.0";

    /// @inheritdoc IBillingContract
    bytes32 public constant BILLING_VOTE_TYPEHASH =
        keccak256("BillingVote(uint64 epoch,RpCount[] counts)RpCount(uint64 rpId,uint64 count)");

    /// @dev EIP-712 typehash for a single RpCount struct (member of a BillingVote).
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
        uint64 rebatePeriodEpochs
    ) public virtual initializer {
        if (oprfKeyRegistry == address(0) || feeToken == address(0) || feeRecipient == address(0)) {
            revert ZeroAddress();
        }

        // registrationFee is unused (0); _feeToken (WLD) and _feeRecipient are reused for payments.
        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, feeRecipient, feeToken, 0);

        _oprfKeyRegistry = IOprfNodeSet(oprfKeyRegistry);

        if (epochLength == 0 || votingWindow == 0 || paymentWindow == 0 || votingWindow > epochLength) {
            revert InvalidTiming();
        }
        if (rebatePeriodEpochs == 0) revert InvalidTiming();

        _genesis = genesis;
        _epochLength = epochLength;
        _votingWindow = votingWindow;
        _paymentWindow = paymentWindow;
        _rebatePeriodEpochs = rebatePeriodEpochs;

        // Store the initial schedule at version 0.
        _validateTiers(tiers);
        _storeTierSchedule(0, tiers);
        emit TierScheduleUpdated(0);
    }

    ////////////////////////////////////////////////////////////
    //                   PUBLIC FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBillingContract
    function submitBillingVotes(uint64 epoch, SignedVote[] calldata votes) external virtual onlyProxy onlyInitialized {
        // The voting window for `epoch` must be currently open.
        uint64 votingStart = epochEnd(epoch);
        if (block.timestamp < votingStart) revert VotingWindowNotOpen();
        if (block.timestamp >= votingStart + _votingWindow) revert VotingWindowClosed();

        // No finalization side effect here: submit only records votes. Finalization is driven
        // solely by the permissionless {finalizeEpochs} (see IBillingContract), so a node's vote
        // gas is predictable and never carries another epoch's finalization cost.

        // Snapshot the node count and fee-schedule version on the epoch's first accepted vote, so
        // quorum/median and pricing stay stable across the voting window even if the live node set
        // or schedule changes mid-window.
        if (_nSnapshot[epoch] == 0) {
            uint16 n = _oprfKeyRegistry.numPeers();
            if (n == 0) revert NoNodesRegistered();
            _nSnapshot[epoch] = n;
            _scheduleVersion[epoch] = _currentScheduleVersion;
        }

        uint256 voteCount = votes.length;
        for (uint256 i = 0; i < voteCount; i++) {
            _recordVote(epoch, votes[i]);
        }

        emit VotesSubmitted(epoch, voteCount);
    }

    /// @inheritdoc IBillingContract
    function pay(RpPayment[] calldata payments) external virtual onlyProxy onlyInitialized {
        // Settles currently-finalized debt only; does not finalize (keeper-driven finalizeEpochs
        // keeps debt current). RPs with no finalized debt are skipped so a batched, permissionless
        // call is not griefable by a debt that was concurrently settled or never accrued.
        uint256 len = payments.length;
        for (uint256 i = 0; i < len; i++) {
            uint64 rpId = payments[i].rpId;
            uint256 debt = _totalOwed[rpId];
            if (debt == 0) continue;
            if (debt > payments[i].maxAmount) revert DebtExceedsMax();

            // Effects before interaction: clear debt/clock before pulling tokens.
            _totalOwed[rpId] = 0;
            _oldestUnpaidDue[rpId] = 0;
            _feeToken.safeTransferFrom(msg.sender, _feeRecipient, debt);

            emit DebtPaid(rpId, msg.sender, debt);
        }
    }

    /// @inheritdoc IBillingContract
    function finalizeEpochs(uint64 uptoEpoch, uint256 maxSteps) external virtual onlyProxy onlyInitialized {
        _finalize(uptoEpoch, maxSteps);
    }

    ////////////////////////////////////////////////////////////
    //                    OWNER FUNCTIONS                     //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBillingContract
    function setTierSchedule(Tier[] calldata tiers) external virtual onlyOwner onlyProxy onlyInitialized {
        _validateTiers(tiers);
        uint32 version = ++_currentScheduleVersion;
        _storeTierSchedule(version, tiers);
        emit TierScheduleUpdated(version);
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
        _epochLength = epochLength;
        _votingWindow = votingWindow;
        _paymentWindow = paymentWindow;
        emit TimingUpdated(epochLength, votingWindow, paymentWindow);
    }

    /// @inheritdoc IBillingContract
    function updateOprfKeyRegistry(address newOprfKeyRegistry) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newOprfKeyRegistry == address(0)) revert ZeroAddress();
        address oldOprfKeyRegistry = address(_oprfKeyRegistry);
        _oprfKeyRegistry = IOprfNodeSet(newOprfKeyRegistry);
        emit OprfKeyRegistryUpdated(oldOprfKeyRegistry, newOprfKeyRegistry);
    }

    /// @inheritdoc IBillingContract
    function setRebatePeriodEpochs(uint64 rebatePeriodEpochs) external virtual onlyOwner onlyProxy onlyInitialized {
        if (rebatePeriodEpochs == 0) revert InvalidTiming();
        _rebatePeriodEpochs = rebatePeriodEpochs;
        emit RebatePeriodUpdated(rebatePeriodEpochs);
    }

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBillingContract
    function is_blocked(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (bool) {
        uint64 due = _oldestUnpaidDue[rpId];
        return _totalOwed[rpId] > 0 && due != 0 && block.timestamp > due;
    }

    /// @inheritdoc IBillingContract
    function epochRequestCount(uint64 epoch, uint64 rpId)
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
    function outstandingDebt(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _totalOwed[rpId];
    }

    /// @inheritdoc IBillingContract
    function DOMAIN_SEPARATOR() external view virtual onlyProxy onlyInitialized returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice The timestamp at which epoch `epoch` ends (and its voting window opens).
    function epochEnd(uint64 epoch) public view virtual returns (uint64) {
        return _genesis + (epoch + 1) * _epochLength;
    }

    /// @notice The OPRF key registry address the node set is read from.
    function getOprfKeyRegistry() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_oprfKeyRegistry);
    }

    /// @inheritdoc IBillingContract
    function getCurrentScheduleVersion() external view virtual onlyProxy onlyInitialized returns (uint32) {
        return _currentScheduleVersion;
    }

    /// @inheritdoc IBillingContract
    function getTierSchedule(uint32 version) external view virtual onlyProxy onlyInitialized returns (Tier[] memory) {
        return _tierSchedules[version];
    }

    /// @inheritdoc IBillingContract
    function getRebatePeriodEpochs() external view virtual onlyProxy onlyInitialized returns (uint64) {
        return _rebatePeriodEpochs;
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /// @dev The payment-due timestamp for `epoch`: end of its voting window plus the payment window.
    function _paymentDue(uint64 epoch) internal view returns (uint64) {
        return epochEnd(epoch) + _votingWindow + _paymentWindow;
    }

    /// @dev The latest epoch whose voting window has fully closed, if any.
    function _latestClosedEpoch() internal view returns (bool exists, uint64 epoch) {
        uint64 minTime = _genesis + _epochLength + _votingWindow; // epochEnd(0) + votingWindow
        if (block.timestamp < minTime) return (false, 0);
        // k = e + 1 for the largest closed epoch e.
        uint64 k = (uint64(block.timestamp) - _genesis - _votingWindow) / _epochLength;
        return (true, k - 1);
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

    /// @dev Finalizes closed epochs in global order, up to `uptoEpoch` and at most `maxSteps`
    ///      units of work (one per RP finalized, one per epoch closed). Resumes mid-epoch via the
    ///      `(_nextEpochToFinalize, _finalizeRpCursor)` cursor so an oversized epoch can never make
    ///      a single call exceed the block gas limit.
    function _finalize(uint64 uptoEpoch, uint256 maxSteps) internal {
        (bool exists, uint64 closed) = _latestClosedEpoch();
        if (!exists) return;
        uint64 target = uptoEpoch < closed ? uptoEpoch : closed;

        uint64 e = _nextEpochToFinalize;
        uint256 cursor = _finalizeRpCursor;
        uint256 steps = 0;

        while (e <= target && steps < maxSteps) {
            uint64[] storage rps = _epochRpList[e];
            uint256 len = rps.length;

            while (cursor < len && steps < maxSteps) {
                _finalizeRp(e, rps[cursor]);
                unchecked {
                    cursor++;
                    steps++;
                }
            }

            if (cursor >= len) {
                // Epoch fully finalized: prune its epoch-level transient state and advance.
                // (No-ops on voteless epochs, which still cost one step so skipping stays bounded.)
                delete _epochRpList[e];
                delete _epochVoterCount[e];
                delete _nSnapshot[e];
                delete _scheduleVersion[e];
                cursor = 0;
                unchecked {
                    e++;
                    steps++;
                }
            } else {
                // Budget exhausted mid-epoch; resume here next call.
                break;
            }
        }

        _nextEpochToFinalize = e;
        _finalizeRpCursor = cursor;
    }

    /// @dev Finalizes a single (epoch, rp): prices its lower-median count through the epoch's pinned
    ///      schedule, accrues debt, emits the audit event, and prunes the raw counts.
    function _finalizeRp(uint64 epoch, uint64 rp) internal {
        uint64 count = _median(epoch, rp);
        delete _epochRpCounts[epoch][rp]; // prune raw counts regardless of outcome

        if (count == 0) return; // below quorum or zero median ⇒ nothing billed, no event

        // Rebate-period accounting: reset the running count when crossing a period boundary.
        uint64 periodIdx = epoch / _rebatePeriodEpochs;
        if (_periodIndex[rp] != periodIdx) {
            _periodIndex[rp] = periodIdx;
            _periodCount[rp] = 0;
        }

        uint256 base = _periodCount[rp];
        uint256 fee = _marginalFee(_scheduleVersion[epoch], base, count);
        _periodCount[rp] = base + count;

        if (fee > 0) {
            if (_totalOwed[rp] == 0) {
                // First unpaid epoch sets the block clock; it has the earliest due time since
                // epochs finalize in ascending order.
                _oldestUnpaidDue[rp] = _paymentDue(epoch);
            }
            _totalOwed[rp] += fee;
        }

        emit EpochRpFinalized(epoch, rp, count, fee);
    }

    /// @dev The lower median of an RP's submitted counts for `epoch`, with missing votes counted as
    ///      zero over the epoch's snapshot voter count, gated on quorum. Returns 0 below quorum or
    ///      for pruned/unseen epochs.
    function _median(uint64 epoch, uint64 rp) internal view returns (uint64) {
        uint16 n = _nSnapshot[epoch];
        if (n == 0) return 0; // no snapshot ⇒ no votes (or pruned)

        uint64 v = _epochVoterCount[epoch];
        if (v < _quorum(n)) return 0;

        uint64[] storage stored = _epochRpCounts[epoch][rp];
        uint256 m = stored.length;
        // Voters who did not report this rp count as 0.
        uint256 zeros = uint256(v) - m;
        // Lower-median index over the v values (0-indexed).
        uint256 idx = (uint256(v) - 1) / 2;
        if (idx < zeros) return 0;

        // Copy the reported counts to memory and insertion-sort (m <= n, tiny).
        uint64[] memory vals = new uint64[](m);
        for (uint256 i = 0; i < m; i++) {
            vals[i] = stored[i];
        }
        for (uint256 i = 1; i < m; i++) {
            uint64 key = vals[i];
            uint256 j = i;
            while (j > 0 && vals[j - 1] > key) {
                vals[j] = vals[j - 1];
                j--;
            }
            vals[j] = key;
        }

        // The sorted full vector is `zeros` zeros followed by the sorted reported values.
        return vals[idx - zeros];
    }

    /// @dev The marginal WLD fee for billing `count` additional requests on top of `base` already
    ///      billed this rebate period, using tier schedule `version` (WIP-107 §6.4 tiered pricing).
    function _marginalFee(uint32 version, uint256 base, uint256 count) internal view returns (uint256 fee) {
        Tier[] storage tiers = _tierSchedules[version];
        uint256 from = base;
        uint256 to = base + count;
        uint256 len = tiers.length;
        for (uint256 i = 0; i < len && from < to; i++) {
            uint256 boundary = tiers[i].upTo;
            if (boundary <= from) continue; // tier already fully consumed by `base`
            uint256 segEnd = boundary < to ? boundary : to;
            fee += (segEnd - from) * tiers[i].rate;
            from = segEnd;
        }
        // The final tier's `upTo == type(uint256).max` guarantees the loop covers [base, base+count).
    }

    /// @dev Validates, authenticates and records a single node's vote for `epoch`.
    function _recordVote(uint64 epoch, SignedVote calldata vote) internal {
        // Validate the counts (strictly ascending rpId, all non-zero) and build the EIP-712
        // hash of the RpCount[] array in a single pass.
        bytes32 countsHash = _validateAndHashCounts(vote.counts);

        // Authenticate by recovered signer, not msg.sender — any party may relay the votes.
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(BILLING_VOTE_TYPEHASH, epoch, countsHash)));
        address signer = ECDSA.recover(digest, vote.signature);

        if (!_isNode(signer)) revert NotANode();
        if (_hasVoted[epoch][signer]) revert AlreadyVoted();
        _hasVoted[epoch][signer] = true;
        _epochVoterCount[epoch] += 1;

        uint256 len = vote.counts.length;
        for (uint256 i = 0; i < len; i++) {
            uint64 rpId = vote.counts[i].rpId;
            // First non-zero count seen for this rp in the epoch ⇒ track it in the rp list.
            if (_epochRpCounts[epoch][rpId].length == 0) {
                _epochRpList[epoch].push(rpId);
            }
            _epochRpCounts[epoch][rpId].push(vote.counts[i].count);
        }
    }

    /// @dev Validates a vote's counts and returns the EIP-712 hash of the RpCount[] array.
    ///      rpIds must be strictly ascending (rejects duplicates and the invalid rpId 0); counts
    ///      must all be non-zero (zero counts are implicit and must be omitted).
    function _validateAndHashCounts(RpCount[] calldata counts) internal pure returns (bytes32) {
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
        return keccak256(abi.encodePacked(hashes));
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

    /// @dev Stores a validated tier schedule at `version`.
    function _storeTierSchedule(uint32 version, Tier[] calldata tiers) internal {
        Tier[] storage schedule = _tierSchedules[version];
        uint256 len = tiers.length;
        for (uint256 i = 0; i < len; i++) {
            schedule.push(tiers[i]);
        }
    }
}
