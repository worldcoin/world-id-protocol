//! Bindings for the WIP-107 Billing Contract.

use alloy::sol;

sol!(
    /// `WorldIDBilling`: RP capacity purchases and World ID registrations (WIP-107 §4.2).
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    WorldIdBilling,
    "abi/WorldIDBillingAbi.json"
);
