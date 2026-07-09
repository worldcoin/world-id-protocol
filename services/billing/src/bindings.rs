//! Contract bindings for the on-chain Billing Contract.
//!
//! Hand-written subset of `IBillingContract` limited to what the billing
//! workers call; see `contracts/src/core/interfaces/IBillingContract.sol` for
//! the full interface and documentation.

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IBillingContract {
        /// Permissionlessly finalize closed epochs up to (and including) `uptoEpoch`,
        /// performing at most `maxSteps` units of finalization work.
        function finalizeEpochs(uint32 uptoEpoch, uint256 maxSteps) external;

        /// The latest epoch that has been fully finalized, if any.
        /// `epoch` is only meaningful when `exists` is true.
        function latestFinalizedEpoch() external view returns (bool exists, uint32 epoch);

        /// The latest epoch whose voting window has fully closed, if any.
        /// `epoch` is only meaningful when `exists` is true.
        function latestClosedEpoch() external view returns (bool exists, uint32 epoch);

        /// The timestamp at which `epoch` ends (and its voting window opens).
        function epochEnd(uint32 epoch) external view returns (uint64);

        /// The current timing era's parameters (epoch length, voting window,
        /// payment window, and the era's start epoch/timestamp).
        function getTiming() external view returns (
            uint64 epochLength,
            uint64 votingWindow,
            uint64 paymentWindow,
            uint32 eraStartEpoch,
            uint64 eraStartTime
        );
    }
}
