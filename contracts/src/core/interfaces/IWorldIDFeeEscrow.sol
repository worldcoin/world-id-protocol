// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IWorldIDFeeEscrow
 * @notice Unidirectional payment channels that pay a `collector` for World ID work authorised by an RP.
 * @dev POC implementation of YABS. Resolutions of spec ambiguities:
 *      - Fee is `cumulativeFee(Σ lane high-water marks) - paid`; only the highest auth per lane needs submitting.
 *      - `settle` is permissionless and incremental; funds always go to `collector`.
 *      - Settlement is allowed while `block.timestamp <= collectionDeadline`; the payer may reclaim after.
 *      - The collector may close (refund payer) at any time.
 *      - `spendKey` is pinned at open and must equal the RpRegistry signer at that moment.
 */
interface IWorldIDFeeEscrow {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    /// @notice Immutable channel terms. Signed by `spendKey` (EIP-712 `OpenChannel`) at open.
    struct ChannelSettings {
        /// The RP whose requests this channel pays for.
        uint64 rpId;
        /// Funds the channel and receives refunds.
        address payer;
        /// RP request-signing key. Must equal the RpRegistry signer for `rpId` at open.
        address spendKey;
        /// Receives settled fees.
        address collector;
        /// ERC20 the channel is denominated in.
        address token;
        /// `IFeeSchedule` pricing this channel.
        address feeSchedule;
        /// Number of independent nonce lanes (lane ids are `[0, laneCount)`).
        uint32 laneCount;
        /// Last unix second at which `settle` is accepted.
        uint64 collectionDeadline;
        /// Disambiguates otherwise-identical channels.
        bytes32 salt;
    }

    /// @notice One signed payment authorisation extracted from a `ProofRequestV2`.
    struct PaymentAuthorization {
        /// `lane << 64 | counter`. `counter` must be > 0.
        uint96 channelNonce;
        /// `SHA256(0x01 || nonce || created_at || expires_at || action?)` of the inner request.
        bytes32 rpRequestDigest;
        /// `spendKey` signature over EIP-712 `PaymentAuthorization`.
        bytes signature;
    }

    /// @notice Channel state.
    struct Channel {
        ChannelSettings settings;
        /// Tokens held for this channel.
        uint256 balance;
        /// Total paid to `collector` so far.
        uint256 paid;
        /// Σ over lanes of the highest settled counter.
        uint256 settledCount;
        /// Block timestamp at open. Zero means the channel does not exist.
        uint64 openedAt;
        /// Set once closed; no further settle/fund.
        bool closed;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    error ChannelAlreadyExists(bytes32 channelId);
    error ChannelNotFound(bytes32 channelId);
    /// @dev Renamed from `ChannelClosed` to avoid colliding with the event of that name.
    error ChannelAlreadyClosed(bytes32 channelId);
    error NotPayer();
    error NotPayerOrCollector();
    error ZeroLaneCount();
    error DeadlineInPast();
    /// @dev `spendKey` does not match the RpRegistry signer for `rpId`.
    error SpendKeyMismatch(address expected, address actual);
    error InvalidRpSignature();
    error InvalidPaymentSignature(uint96 channelNonce);
    error InvalidLane(uint32 lane, uint32 laneCount);
    error ZeroCounter();
    /// @dev Counter is not above the lane's high-water mark (replay or out-of-order).
    error StaleNonce(uint32 lane, uint64 counter, uint64 highWater);
    error CollectionWindowClosed(uint64 deadline);
    error CollectionWindowOpen(uint64 deadline);

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    event ChannelOpened(
        bytes32 indexed channelId, uint64 indexed rpId, address indexed collector, address payer, uint256 deposit
    );
    event ChannelFunded(bytes32 indexed channelId, address indexed from, uint256 amount);
    /// @param settledCount Σ lane high-water marks after this settlement.
    /// @param paidNow Tokens transferred to the collector in this call.
    /// @param outstanding Fee accrued but unpaid because the channel is underfunded.
    event ChannelSettled(bytes32 indexed channelId, uint256 settledCount, uint256 paidNow, uint256 outstanding);
    event ChannelClosed(bytes32 indexed channelId, uint256 paidToCollector, uint256 refundedToPayer);
    /// @notice `cumulativeFee` reverted during `closeChannel`; the fee was treated as zero and the payer fully refunded.
    /// @dev The payer's exit must never depend on a third-party schedule contract behaving.
    event FeeScheduleFailed(bytes32 indexed channelId);

    ////////////////////////////////////////////////////////////
    //                   STATE-CHANGING                       //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Opens a channel and deposits `deposit` tokens from `msg.sender` (must be `settings.payer`).
     * @param rpSignature `spendKey` signature over EIP-712 `OpenChannel(settings)`.
     */
    function openChannel(ChannelSettings calldata settings, uint256 deposit, bytes calldata rpSignature)
        external
        returns (bytes32 channelId);

    /// @notice Adds `amount` tokens from `msg.sender` to the channel. Anyone may fund.
    function fund(bytes32 channelId, uint256 amount) external;

    /**
     * @notice Advances lane high-water marks with the given authorisations and pays the collector what is owed.
     * @dev Permissionless. Passing an empty array collects any outstanding balance without new authorisations.
     * @return paidNow Tokens transferred to the collector.
     */
    function settle(bytes32 channelId, PaymentAuthorization[] calldata auths) external returns (uint256 paidNow);

    /**
     * @notice Pays any outstanding fee to the collector and refunds the rest to the payer.
     * @dev Callable by the collector at any time, or by the payer once `block.timestamp > collectionDeadline`.
     */
    function closeChannel(bytes32 channelId) external;

    ////////////////////////////////////////////////////////////
    //                         VIEWS                          //
    ////////////////////////////////////////////////////////////

    /// @notice `keccak256(abi.encode(block.chainid, address(this), settings))`.
    function computeChannelId(ChannelSettings calldata settings) external view returns (bytes32);

    function getChannel(bytes32 channelId) external view returns (Channel memory);

    /// @notice Highest settled counter for `lane`.
    function laneHighWater(bytes32 channelId, uint32 lane) external view returns (uint64);

    /**
     * @notice Solvency primitive for collectors: fee owed if the channel's settled count reached `totalCount`.
     * @return owed `cumulativeFee(totalCount) - paid`.
     * @return balance Current channel balance.
     */
    function quote(bytes32 channelId, uint256 totalCount) external view returns (uint256 owed, uint256 balance);

    /// @notice EIP-712 signing hash for `PaymentAuthorization` on this escrow.
    function paymentAuthorizationHash(bytes32 channelId, uint64 rpId, uint96 channelNonce, bytes32 rpRequestDigest)
        external
        view
        returns (bytes32);

    /// @notice EIP-712 signing hash for `OpenChannel` on this escrow.
    function openChannelHash(ChannelSettings calldata settings) external view returns (bytes32);

    function domainSeparatorV4() external view returns (bytes32);

    function getRpRegistry() external view returns (address);
}
