//! Contract bindings for the on-chain Billing Contract.
use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IBillingContract {
        /// Permissionlessly finalize closed epochs up to (and including) `uptoEpoch`,
        /// performing at most `maxSteps` units of finalization work.
        function finalizeEpochs(uint32 uptoEpoch, uint256 maxSteps) external;

        /// The latest finalized and latest closed epoch watermarks, read together in one call
        /// (consistent snapshot from a single block, avoiding read skew between two calls).
        /// Each `epoch` is only meaningful when its corresponding `exists` flag is true.
        function epochWatermarks()
            external
            view
            returns (bool finalizedExists, uint32 finalizedEpoch, bool closedExists, uint32 closedEpoch);

        /// The timestamp at which `epoch`'s voting window closes (i.e. when it
        /// becomes eligible to finalize). Exact across timing-era boundaries.
        function votingWindowEnd(uint32 epoch) external view returns (uint64);
    }
}
