// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {WorldIDBase} from "./abstract/WorldIDBase.sol";
import {IRpRegistry} from "./interfaces/IRpRegistry.sol";
import {IWorldIDFeeEscrow} from "./interfaces/IWorldIDFeeEscrow.sol";

/**
 * @title WorldIDFeeEscrow (World ID)
 * @author World Contributors
 * @notice Fixed-rate, epoch-based payment channels that pay a `collector` for World ID work authorised by an RP.
 * @dev The EIP-712 `verifyingContract` is the proxy, so every `channelId` and payment digest is bound to the
 *      proxy address rather than to an implementation. Reentrancy is guarded with transient storage, which
 *      keeps the guard out of the upgradeable storage layout entirely.
 * @custom:repo https://github.com/world-id/world-id-protocol
 */
contract WorldIDFeeEscrow is WorldIDBase, ReentrancyGuardTransient, IWorldIDFeeEscrow {
    using SafeERC20 for IERC20;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    // DO NOT REORDER! To ensure compatibility between upgrades, it is exceedingly important
    // that no reordering of these variables takes place. If reordering happens, a storage
    // clash will occur (effectively a memory safety error).

    /// @dev Registry consulted at open to pin `spendKey` to the RP's registered signer.
    IRpRegistry internal _rpRegistry;

    /// @dev channelId -> immutable settings. A zero `spendKey` means the channel does not exist.
    mapping(bytes32 => ChannelSettings) internal _channels;

    /// @dev channelId -> epoch -> state
    mapping(bytes32 => mapping(uint64 => EpochState)) internal _epochs;

    /// @dev channelId -> epoch -> lane -> highest settled counter
    mapping(bytes32 => mapping(uint64 => mapping(uint32 => uint64))) internal _laneHighWater;

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant EIP712_NAME = "WorldIDFeeEscrow";
    string public constant EIP712_VERSION = "1";

    bytes32 public constant CHANNEL_SETTINGS_TYPEHASH = keccak256(
        "ChannelSettings(uint64 rpId,address spendKey,address collector,address token,uint256 pricePerUnit,uint64 epochLength,uint64 epochZero,bytes32 salt)"
    );

    bytes32 public constant PAYMENT_AUTHORIZATION_TYPEHASH =
        keccak256("PaymentAuthorization(bytes32 channelId,uint64 epoch,uint96 channelNonce)");

    ////////////////////////////////////////////////////////////
    //                      Constructor                       //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract.
    /// @param rpRegistry The `RpRegistry` used to resolve the RP signer at channel open.
    function initialize(address rpRegistry) public virtual initializer {
        if (rpRegistry == address(0)) revert ZeroAddress();

        // The escrow charges no registration fee, so the fee configuration stays empty.
        __BaseUpgradeable_init(EIP712_NAME, EIP712_VERSION, address(0), address(0), 0);
        _rpRegistry = IRpRegistry(rpRegistry);
    }

    ////////////////////////////////////////////////////////////
    //                    PUBLIC FUNCTIONS                    //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IWorldIDFeeEscrow
    function openChannel(ChannelSettings calldata settings)
        external
        virtual
        onlyProxy
        onlyInitialized
        returns (bytes32 channelId)
    {
        if (settings.spendKey == address(0) || settings.collector == address(0) || settings.token == address(0)) {
            revert ZeroAddress();
        }
        if (settings.pricePerUnit == 0 || settings.epochLength == 0) revert ZeroValue();

        // Reverts for unknown or inactive RPs.
        (, address signer) = _rpRegistry.getOprfKeyIdAndSigner(settings.rpId);
        if (signer != settings.spendKey) revert SpendKeyMismatch(signer, settings.spendKey);

        channelId = computeChannelId(settings);
        if (_channels[channelId].spendKey != address(0)) revert ChannelAlreadyExists(channelId);

        _channels[channelId] = settings;

        emit ChannelOpened(channelId, settings);
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function fund(bytes32 channelId, uint64 epoch, uint256 amount)
        external
        virtual
        onlyProxy
        onlyInitialized
        nonReentrant
    {
        ChannelSettings storage settings = _channelOrRevert(channelId);
        EpochState storage state = _epochs[channelId][epoch];

        if (state.closed) revert EpochClosed(channelId, epoch);
        if (block.timestamp >= _epochEnd(settings, epoch)) revert EpochEnded(channelId, epoch);

        uint256 pricePerUnit = settings.pricePerUnit;
        if (amount == 0) revert ZeroValue();
        if (amount % pricePerUnit != 0) revert AmountNotMultipleOfPrice(amount, pricePerUnit);

        state.funded += amount;

        emit EpochFunded(channelId, epoch, msg.sender, amount);

        IERC20(settings.token).safeTransferFrom(msg.sender, address(this), amount);
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function settle(bytes32 channelId, uint64 epoch, PaymentAuthorization[] calldata auths)
        external
        virtual
        onlyProxy
        onlyInitialized
        nonReentrant
    {
        ChannelSettings storage settings = _channelOrRevert(channelId);
        EpochState storage state = _epochs[channelId][epoch];

        if (state.closed) revert EpochClosed(channelId, epoch);

        address spendKey = settings.spendKey;
        uint256 pricePerUnit = settings.pricePerUnit;
        mapping(uint32 => uint64) storage marks = _laneHighWater[channelId][epoch];

        uint64 added;
        for (uint256 i = 0; i < auths.length; i++) {
            PaymentAuthorization calldata auth = auths[i];
            uint32 lane = uint32(auth.channelNonce >> 64);
            uint64 counter = uint64(auth.channelNonce);

            if (counter == 0) revert ZeroCounter();

            // A running mark, so duplicate lanes within one batch settle to the batch maximum and a
            // replayed batch is a no-op rather than a revert. Stale entries are never signature-checked.
            uint64 previous = marks[lane];
            if (counter <= previous) continue;

            bytes32 digest = paymentAuthorizationDigest(channelId, epoch, auth.channelNonce);
            if (!_isValidSpendKeySignature(spendKey, digest, auth.signature)) {
                revert InvalidPaymentSignature(auth.channelNonce);
            }

            marks[lane] = counter;
            added += counter - previous;
        }

        uint256 funded = state.funded;
        uint64 settledUnits = state.settledUnits + added;

        // Equivalent to `settledUnits * pricePerUnit > funded`, without the multiplication overflowing.
        uint256 capacity = funded / pricePerUnit;
        if (settledUnits > capacity) revert CapacityExceeded(settledUnits, capacity);

        state.settledUnits = settledUnits;

        uint256 paid = pricePerUnit * added;

        bool closed = block.timestamp >= _epochEnd(settings, epoch);
        if (closed) {
            // The non-refundable part of the price. Claims nothing about usage, so it needs no signatures.
            state.closed = true;
            paid += funded - pricePerUnit * settledUnits;
        }

        emit EpochSettled(channelId, epoch, settledUnits, paid, closed);

        if (paid > 0) IERC20(settings.token).safeTransfer(settings.collector, paid);
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
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CHANNEL_SETTINGS_TYPEHASH,
                    settings.rpId,
                    settings.spendKey,
                    settings.collector,
                    settings.token,
                    settings.pricePerUnit,
                    settings.epochLength,
                    settings.epochZero,
                    settings.salt
                )
            )
        );
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function paymentAuthorizationDigest(bytes32 channelId, uint64 epoch, uint96 channelNonce)
        public
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (bytes32)
    {
        return _hashTypedDataV4(keccak256(abi.encode(PAYMENT_AUTHORIZATION_TYPEHASH, channelId, epoch, channelNonce)));
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function epochState(bytes32 channelId, uint64 epoch)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (EpochState memory)
    {
        return _epochs[channelId][epoch];
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function laneHighWater(bytes32 channelId, uint64 epoch, uint32 lane)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint64)
    {
        return _laneHighWater[channelId][epoch][lane];
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function channelSettings(bytes32 channelId)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (ChannelSettings memory)
    {
        return _channelOrRevert(channelId);
    }

    /// @inheritdoc IWorldIDFeeEscrow
    function epochEnd(bytes32 channelId, uint64 epoch)
        external
        view
        virtual
        onlyProxy
        onlyInitialized
        returns (uint256)
    {
        return _epochEnd(_channelOrRevert(channelId), epoch);
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

    /// @dev Settings of `channelId`, reverting if no channel was ever opened under it.
    function _channelOrRevert(bytes32 channelId) internal view virtual returns (ChannelSettings storage settings) {
        settings = _channels[channelId];
        if (settings.spendKey == address(0)) revert ChannelNotFound(channelId);
    }

    /**
     * @dev First timestamp at which `epoch` is over. Widened to `uint256` before multiplying, so the
     *      largest expressible epoch and epoch length still compute exactly rather than wrapping.
     */
    function _epochEnd(ChannelSettings storage settings, uint64 epoch) internal view virtual returns (uint256) {
        return uint256(settings.epochZero) + (uint256(epoch) + 1) * uint256(settings.epochLength);
    }

    /**
     * @dev True if `signature` is a canonical 65-byte ECDSA signature by `spendKey` over `digest`.
     *      `tryRecover` already rejects a wrong length, a high `s`, and a `v` outside {27, 28}, and
     *      returns the zero address on failure, which no `spendKey` can equal. Contract signers are
     *      out of scope: an ERC-1271 `spendKey` could change its own answer after the RP signed.
     */
    function _isValidSpendKeySignature(address spendKey, bytes32 digest, bytes calldata signature)
        internal
        pure
        virtual
        returns (bool)
    {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, signature);
        return err == ECDSA.RecoverError.NoError && recovered == spendKey;
    }
}
