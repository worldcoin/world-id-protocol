// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IWorldIDFeeEscrow
 * @author World Contributors
 * @notice Fixed-rate, epoch-based payment channels that pay a `collector` for World ID work
 *         authorised by an RP.
 * @dev Per-epoch invariants, all enforced by {IWorldIDFeeEscrow-settle} and {IWorldIDFeeEscrow-fund}:
 *      - `capacity = funded / pricePerUnit` and `settledUnits <= capacity`.
 *      - `balance = funded - pricePerUnit * settledUnits` until closed, then zero.
 *      - Once closed, everything funded has reached the collector. No path returns tokens to a funder.
 */
interface IWorldIDFeeEscrow {
    ////////////////////////////////////////////////////////////
    //                        STRUCTS                         //
    ////////////////////////////////////////////////////////////

    /// @notice Immutable channel terms. Never signed; its EIP-712 digest is the `channelId`.
    struct ChannelSettings {
        /// RP whose requests this channel pays for.
        uint64 rpId;
        /// RP registry signer at open. Signs every `PaymentAuthorization`.
        address spendKey;
        /// Receives every token funded into the channel.
        address collector;
        /// Exact-transfer ERC-20 the channel is denominated in.
        address token;
        /// Price of one unit, in `token`'s smallest unit.
        uint256 pricePerUnit;
        /// Epoch length in seconds.
        uint64 epochLength;
        /// Unix timestamp at which epoch 0 begins.
        uint64 epochZero;
        /// Disambiguates otherwise-identical channels.
        bytes32 salt;
    }

    /// @notice One signed payment authorisation. `epoch` is the settle call's argument, not repeated here.
    struct PaymentAuthorization {
        /// `lane << 64 | counter`, `counter >= 1`.
        uint96 channelNonce;
        /// `spendKey` signature over EIP-712 `PaymentAuthorization`. Canonical 65-byte ECDSA only.
        bytes signature;
    }

    /// @notice Per `(channelId, epoch)` state. Capacity and balance are derived from it.
    struct EpochState {
        /// Tokens funded into this epoch.
        uint256 funded;
        /// Sum of lane high-water marks.
        uint64 settledUnits;
        /// True once the closing settlement has paid the remainder.
        bool closed;
    }

    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /// @dev A zero address in `settings` reverts with `WorldIDBase.ZeroAddress`, declared on the base.
    /// @dev `pricePerUnit`, `epochLength`, or a funded `amount` is zero.
    error ZeroValue();
    error ChannelAlreadyExists(bytes32 channelId);
    error ChannelNotFound(bytes32 channelId);
    /// @dev `spendKey` does not match the RpRegistry signer for `rpId`.
    error SpendKeyMismatch(address expected, address actual);
    /// @dev Funding an epoch whose window has already elapsed.
    error EpochEnded(bytes32 channelId, uint64 epoch);
    /// @dev The closing settlement already ran for this epoch.
    error EpochClosed(bytes32 channelId, uint64 epoch);
    /// @dev Funding must buy whole units, so the escrow never holds an unspendable fraction.
    error AmountNotMultipleOfPrice(uint256 amount, uint256 pricePerUnit);
    /// @dev Counter zero proves no units, so it is never a valid authorisation.
    error ZeroCounter();
    error InvalidPaymentSignature(uint96 channelNonce);
    /// @dev The batch would admit more units than the epoch's funding bought.
    error CapacityExceeded(uint64 settledUnits, uint256 capacity);

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    event ChannelOpened(bytes32 indexed channelId, ChannelSettings settings);
    event EpochFunded(bytes32 indexed channelId, uint64 indexed epoch, address funder, uint256 amount);
    /// @param settledUnits Sum of lane high-water marks after this settlement.
    /// @param paid Tokens transferred to the collector in this call, including any closing remainder.
    /// @param closed True if this call was the closing settlement.
    event EpochSettled(bytes32 indexed channelId, uint64 indexed epoch, uint64 settledUnits, uint256 paid, bool closed);

    ////////////////////////////////////////////////////////////
    //                   STATE-CHANGING                       //
    ////////////////////////////////////////////////////////////

    /**
     * @notice Registers a channel. Anyone may call.
     * @dev `spendKey` must equal the RpRegistry signer for `rpId`, which also requires an active RP.
     *      No RP signature is required: the RP consents by signing its first `PaymentAuthorization`
     *      naming this `channelId`, which it can only do after reading the settings the id commits to.
     */
    function openChannel(ChannelSettings calldata settings) external returns (bytes32 channelId);

    /**
     * @notice Buys capacity for the current or a future epoch. Anyone may fund.
     * @dev `amount` must be a nonzero multiple of `pricePerUnit`. Capacity rises in the same block.
     *      Funding is a purchase: the funder holds no claim afterwards.
     */
    function fund(bytes32 channelId, uint64 epoch, uint256 amount) external;

    /**
     * @notice Raises lane marks for `epoch` and pays `pricePerUnit * newUnits` to the collector.
     * @dev Anyone may call. Authorisations at or below their lane's mark are skipped, not rejected, so a
     *      replayed batch pays zero. Once `block.timestamp >= epochEnd`, the same call also pays the
     *      remaining balance and closes the epoch; an empty batch is then the plain close.
     */
    function settle(bytes32 channelId, uint64 epoch, PaymentAuthorization[] calldata auths) external;

    ////////////////////////////////////////////////////////////
    //                         VIEWS                          //
    ////////////////////////////////////////////////////////////

    /// @notice The EIP-712 digest of `settings` under this escrow's domain.
    function computeChannelId(ChannelSettings calldata settings) external view returns (bytes32);

    function epochState(bytes32 channelId, uint64 epoch) external view returns (EpochState memory);

    /// @notice Highest settled counter for `lane` in `epoch`.
    function laneHighWater(bytes32 channelId, uint64 epoch, uint32 lane) external view returns (uint64);

    /// @notice Settings of an open channel. Reverts if the channel does not exist.
    function channelSettings(bytes32 channelId) external view returns (ChannelSettings memory);

    /// @notice First timestamp at which `epoch` is over, i.e. `epochZero + (epoch + 1) * epochLength`.
    function epochEnd(bytes32 channelId, uint64 epoch) external view returns (uint256);

    /// @notice EIP-712 signing digest a `spendKey` must produce for one authorisation.
    function paymentAuthorizationDigest(bytes32 channelId, uint64 epoch, uint96 channelNonce)
        external
        view
        returns (bytes32);

    function domainSeparatorV4() external view returns (bytes32);

    function getRpRegistry() external view returns (address);
}
