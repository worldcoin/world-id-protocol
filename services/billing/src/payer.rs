//! Payer worker: settles finalized epoch fees in WLD.
//!
//! Acts as a permissionless paymaster: it watches for finalized epochs with a
//! non-zero billed count and calls `pay` on the Billing Contract to settle each
//! relying party's outstanding WLD debt before its `voting_end + payment_window`
//! deadline. Payments are batched across relying parties and open epochs, each
//! guarded by a per-RP `max_amount` cap that protects against debt accruing
//! between transaction construction and inclusion.
//!
//! Not yet implemented.
