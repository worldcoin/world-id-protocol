//! World ID billing service.
//!
//! Off-chain operator service for WIP-107 experimental transactional fees. It
//! runs two independently-deployable workers against the on-chain Billing
//! Contract on World Chain:
//!
//! - [`finalizer`]: the permissionless keeper that drives epoch finalization
//!   via `finalizeEpochs` once voting windows close (finalization is
//!   keeper-driven in the contract and must be triggered by a third party).
//! - [`payer`]: settles finalized epoch fees in WLD on behalf of relying
//!   parties before the payment deadline (a permissionless paymaster).
//!
//! The two workers share this crate's contract bindings, provider stack,
//! configuration, and telemetry (a modular monolith). Each worker can be
//! enabled independently so they can be deployed as separate processes from
//! the same image, which keeps their signing keys and blast radius isolated.

pub mod bindings;
pub mod cli;
pub mod finalizer;
pub mod metrics;
pub mod payer;
