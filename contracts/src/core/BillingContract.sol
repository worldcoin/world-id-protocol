// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

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
 *      Finalization is event-driven: each {submitBillingVotes} flushes now-closed epochs and prunes
 *      their raw vote data, so raw state scales with participants, not time.
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
        // Implemented in "Vote submission" + "Event-driven finalization" steps.
        revert NotImplemented();
    }

    /// @inheritdoc IBillingContract
    function pay(RpPayment[] calldata payments) external virtual onlyProxy onlyInitialized {
        // Implemented in "Payment + blocking" step.
        revert NotImplemented();
    }

    /// @inheritdoc IBillingContract
    function finalizeEpochs(uint64) external virtual onlyProxy onlyInitialized {
        // Implemented in "Event-driven finalization" step.
        revert NotImplemented();
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

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBillingContract
    function is_blocked(uint64 rpId) external view virtual onlyProxy onlyInitialized returns (bool) {
        uint64 due = _oldestUnpaidDue[rpId];
        return _totalOwed[rpId] > 0 && due != 0 && block.timestamp > due;
    }

    /// @inheritdoc IBillingContract
    function epochRequestCount(uint64, uint64) external view virtual onlyProxy onlyInitialized returns (uint64) {
        // Implemented in "Event-driven finalization" step (median over retained epochs).
        revert NotImplemented();
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

    ////////////////////////////////////////////////////////////
    //                    UPGRADE / TEMP                      //
    ////////////////////////////////////////////////////////////

    // TODO(billing-v1): removed once all functions are implemented across the plan's steps.
    error NotImplemented();
}
