// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {WorldIDBase} from "./abstract/WorldIDBase.sol";
import {IFeeSchedule} from "./interfaces/IFeeSchedule.sol";
import {IRpRegistry} from "./interfaces/IRpRegistry.sol";
import {IWorldIDFeeEscrow} from "./interfaces/IWorldIDFeeEscrow.sol";

/**
 * @title WorldIDFeeEscrow (World ID)
 * @author World Contributors
 * @notice Unidirectional payment channels that pay a `collector` for World ID work authorised by an RP.
 * @dev POC implementation of YABS. See {IWorldIDFeeEscrow} for the resolved spec semantics.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDFeeEscrow is WorldIDBase, IWorldIDFeeEscrow {
    using SafeERC20 for IERC20;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev Registry consulted at open to pin `spendKey` to the RP's registered signer.
    IRpRegistry internal _rpRegistry;

    /// @dev channelId -> channel state
    mapping(bytes32 => Channel) internal _channels;

    /// @dev channelId -> lane -> highest settled counter
    mapping(bytes32 => mapping(uint32 => uint64)) internal _laneHighWater;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "WorldIDFeeEscrow";
    string public constant EIP712_VERSION = "1.0";

    bytes32 public constant OPEN_CHANNEL_TYPEHASH = keccak256(
        "OpenChannel(uint64 rpId,address payer,address spendKey,address collector,address token,address feeSchedule,uint32 laneCount,uint64 collectionDeadline,bytes32 salt)"
    );

    bytes32 public constant PAYMENT_AUTHORIZATION_TYPEHASH =
        keccak256("PaymentAuthorization(bytes32 channelId,uint64 rpId,uint96 channelNonce,bytes32 rpRequestDigest)");

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract.
    /// @param rpRegistry The `RpRegistry` used to resolve the RP signer at channel open.
    function initialize(address rpRegistry) public virtual initializer {
        if (rpRegistry == address(0)) revert ZeroAddress();

        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, address(0), address(0), 0);
        _rpRegistry = IRpRegistry(rpRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                    PUBLIC FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDFeeEscrow
    function openChannel(ChannelSettings calldata settings, uint256 deposit, bytes calldata rpSignature)
        external
        virtual
        onlyProxy
        onlyInitialized
        returns (bytes32 channelId)
    {
        if (msg.sender != settings.payer) revert NotPayer();
        if (settings.laneCount == 0) revert ZeroLaneCount();
        if (settings.collectionDeadline <= block.timestamp) {
            revert DeadlineInPast();
        }
        if (
            settings.spendKey == address(0) || settings.collector == address(0) || settings.token == address(0)
                || settings.feeSchedule == address(0)
        ) {
            revert ZeroAddress();
        }

        // Reverts for unknown or inactive RPs.
        (, address signer) = _rpRegistry.getOprfKeyIdAndSigner(settings.rpId);
        if (signer != settings.spendKey) {
            revert SpendKeyMismatch(signer, settings.spendKey);
        }

        if (!SignatureChecker.isValidSignatureNow(settings.spendKey, openChannelHash(settings), rpSignature)) {
            revert InvalidRpSignature();
        }

        channelId = computeChannelId(settings);
        Channel storage channel = _channels[channelId];
        if (channel.openedAt != 0) revert ChannelAlreadyExists(channelId);

        channel.settings = settings;
        channel.openedAt = uint64(block.timestamp);
        channel.balance = deposit;

        emit ChannelOpened(channelId, settings.rpId, settings.collector, settings.payer, deposit);

        if (deposit > 0) {
            IERC20(settings.token).safeTransferFrom(msg.sender, address(this), deposit);
        }
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function fund(bytes32 channelId, uint256 amount) external virtual onlyProxy onlyInitialized {
        Channel storage channel = _channels[channelId];
        if (channel.openedAt == 0) revert ChannelNotFound(channelId);
        if (channel.closed) revert ChannelAlreadyClosed(channelId);

        channel.balance += amount;

        emit ChannelFunded(channelId, msg.sender, amount);

        if (amount > 0) {
            IERC20(channel.settings.token).safeTransferFrom(msg.sender, address(this), amount);
        }
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function settle(bytes32 channelId, PaymentAuthorization[] calldata auths)
        external
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256 paidNow)
    {
        Channel storage channel = _channels[channelId];
        if (channel.openedAt == 0) revert ChannelNotFound(channelId);
        if (channel.closed) revert ChannelAlreadyClosed(channelId);

        uint64 deadline = channel.settings.collectionDeadline;
        if (block.timestamp > deadline) revert CollectionWindowClosed(deadline);

        uint32 laneCount = channel.settings.laneCount;
        address spendKey = channel.settings.spendKey;
        uint64 rpId = channel.settings.rpId;
        mapping(uint32 => uint64) storage highWater = _laneHighWater[channelId];

        uint256 added;
        for (uint256 i = 0; i < auths.length; i++) {
            PaymentAuthorization calldata auth = auths[i];
            uint32 lane = uint32(auth.channelNonce >> 64);
            uint64 counter = uint64(auth.channelNonce);

            if (lane >= laneCount) revert InvalidLane(lane, laneCount);
            if (counter == 0) revert ZeroCounter();

            uint64 previous = highWater[lane];
            if (counter <= previous) revert StaleNonce(lane, counter, previous);

            bytes32 digest = paymentAuthorizationHash(channelId, rpId, auth.channelNonce, auth.rpRequestDigest);
            if (!SignatureChecker.isValidSignatureNow(spendKey, digest, auth.signature)) {
                revert InvalidPaymentSignature(auth.channelNonce);
            }

            highWater[lane] = counter;
            added += counter - previous;
        }

        if (added > 0) channel.settledCount += added;

        uint256 outstanding;
        (paidNow, outstanding) = _payOut(channelId);

        emit ChannelSettled(channelId, channel.settledCount, paidNow, outstanding);
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function closeChannel(bytes32 channelId) external virtual onlyProxy onlyInitialized {
        Channel storage channel = _channels[channelId];
        if (channel.openedAt == 0) revert ChannelNotFound(channelId);
        if (channel.closed) revert ChannelAlreadyClosed(channelId);

        uint64 deadline = channel.settings.collectionDeadline;
        if (msg.sender != channel.settings.collector) {
            if (msg.sender != channel.settings.payer) {
                revert NotPayerOrCollector();
            }
            if (block.timestamp <= deadline) {
                revert CollectionWindowOpen(deadline);
            }
        }

        channel.closed = true;

        // The payer's exit must not depend on the schedule contract behaving. A schedule that reverts
        // or overflows would otherwise lock the deposit here forever; treat the fee as zero instead.
        uint256 paidToCollector;
        try IFeeSchedule(channel.settings.feeSchedule).cumulativeFee(channel.settledCount) returns (
            uint256 cumulative
        ) {
            (paidToCollector,) = _disburse(channelId, cumulative);
        } catch {
            emit FeeScheduleFailed(channelId);
        }

        uint256 refund = channel.balance;
        channel.balance = 0;

        emit ChannelClosed(channelId, paidToCollector, refund);

        if (refund > 0) {
            IERC20(channel.settings.token).safeTransfer(channel.settings.payer, refund);
        }
    }

    ////////////////////////////////////////////////////////////
    //                    VIEW FUNCTIONS                      //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDFeeEscrow
    function computeChannelId(ChannelSettings calldata settings)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), settings));
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function getChannel(bytes32 channelId) external view virtual onlyProxy onlyInitialized returns (Channel memory) {
        return _channels[channelId];
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function laneHighWater(bytes32 channelId, uint32 lane)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint64)
    {
        return _laneHighWater[channelId][lane];
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function quote(bytes32 channelId, uint256 totalCount)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256 owed, uint256 balance)
    {
        Channel storage channel = _channels[channelId];
        if (channel.openedAt == 0) revert ChannelNotFound(channelId);

        uint256 cumulative = IFeeSchedule(channel.settings.feeSchedule).cumulativeFee(totalCount);
        uint256 paid = channel.paid;
        owed = cumulative > paid ? cumulative - paid : 0;
        balance = channel.balance;
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function paymentAuthorizationHash(bytes32 channelId, uint64 rpId, uint96 channelNonce, bytes32 rpRequestDigest)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(PAYMENT_AUTHORIZATION_TYPEHASH, channelId, rpId, channelNonce, rpRequestDigest))
        );
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function openChannelHash(ChannelSettings calldata settings)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    OPEN_CHANNEL_TYPEHASH,
                    settings.rpId,
                    settings.payer,
                    settings.spendKey,
                    settings.collector,
                    settings.token,
                    settings.feeSchedule,
                    settings.laneCount,
                    settings.collectionDeadline,
                    settings.salt
                )
            )
        );
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function domainSeparatorV4() public view virtual onlyProxy onlyInitialized returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function getRpRegistry() public view virtual onlyProxy onlyInitialized returns (address) {
        return address(_rpRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                   INTERNAL FUNCTIONS                   //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Pays the collector `cumulativeFee(settledCount) - paid`, capped at the channel balance.
     *      `feeSchedule` is pinned at open and agreed by both parties, so it is trusted here; state is
     *      still read after the call and written before the transfer so a reentrant schedule can only
     *      underpay itself. Strict: a reverting schedule reverts the settlement, since the collector chose it.
     * @return paidNow Tokens transferred to the collector.
     * @return outstanding Fee accrued but unpayable because the channel is underfunded.
     */
    function _payOut(bytes32 channelId) internal virtual returns (uint256 paidNow, uint256 outstanding) {
        Channel storage channel = _channels[channelId];
        uint256 cumulative = IFeeSchedule(channel.settings.feeSchedule).cumulativeFee(channel.settledCount);
        return _disburse(channelId, cumulative);
    }

    /**
     * @dev Pays the collector `cumulative - paid`, capped at the channel balance. Split out of {_payOut} so
     *      {closeChannel} can supply a cumulative fee obtained from a fallible call.
     * @return paidNow Tokens transferred to the collector.
     * @return outstanding Fee accrued but unpayable because the channel is underfunded.
     */
    function _disburse(bytes32 channelId, uint256 cumulative)
        internal
        virtual
        returns (uint256 paidNow, uint256 outstanding)
    {
        Channel storage channel = _channels[channelId];

        uint256 paid = channel.paid;
        // A non-monotonic schedule would underflow here; treat it as nothing owed instead.
        uint256 owed = cumulative > paid ? cumulative - paid : 0;

        uint256 balance = channel.balance;
        paidNow = owed < balance ? owed : balance;
        outstanding = owed - paidNow;

        if (paidNow > 0) {
            channel.paid = paid + paidNow;
            channel.balance = balance - paidNow;
            IERC20(channel.settings.token).safeTransfer(channel.settings.collector, paidNow);
        }
    }
}
