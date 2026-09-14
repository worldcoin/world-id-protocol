//! Fixed-rate epoch payment channels between a relying party and a collector.
//!
//! Funding an epoch buys capacity at a fixed `pricePerUnit`. Each unit of paid work is a
//! standalone [`Payment`]: a channel id, an epoch, a `lane << 64 | counter` nonce, and the
//! RP's `spendKey` signature over an EIP-712 `PaymentAuthorization`. Counters are cumulative,
//! so one signature per lane proves the epoch's whole usage and settlement costs one signature
//! per lane rather than one per unit.
//!
//! A `Payment` names no request, so `ProofRequest` and every party that verifies it are
//! untouched. Binding a payment to one request is deferred to a later version.
//!
//! The RP holds no nonce state. A collector issues counters and proves each proposal with the
//! RP's own signature on the counter below it, which the RP checks statelessly with
//! [`verify_predecessor`]. A reservation is signed too, with [`verify_reservation`]: it holds
//! capacity for its lifetime, so an unsigned one would let anybody starve the channel.
//!
//! This crate is the protocol, not a collector. It signs, verifies, and hashes; deciding what
//! to serve and settling it are the collector's business.
//!
//! ```no_run
//! use alloy::signers::local::PrivateKeySigner;
//! use world_id_channel::{
//!     Payment, verify_predecessor,
//!     typed_data::{ChannelSettings, domain},
//! };
//!
//! # fn run(
//! #     spend_key: PrivateKeySigner,
//! #     escrow: alloy_primitives::Address,
//! #     settings: ChannelSettings,
//! #     lane_nonce: world_id_channel::LaneNonce,
//! #     previous: Option<Payment>,
//! #     epoch: u64,
//! # ) -> eyre::Result<()> {
//! let domain = domain(480, escrow);
//! let channel_id = settings.channel_id(&domain);
//!
//! // The collector proposed a counter; believe it only if it holds the previous signature.
//! verify_predecessor(
//!     previous.as_ref(),
//!     channel_id,
//!     epoch,
//!     lane_nonce,
//!     spend_key.address(),
//!     &domain,
//! )?;
//!
//! let payment = Payment::sign(channel_id, epoch, lane_nonce, &spend_key, &domain)?;
//! # Ok(()) }
//! ```
//!
pub mod nonce;
pub mod payment;
pub mod typed_data;

pub use nonce::{LaneNonce, NonceError};
pub use payment::{
    Payment, PaymentError, ReservationError, verify_predecessor, verify_reservation,
};
pub use typed_data::{
    ChannelSettings, NonceReservation, PaymentAuthorization, RESERVATION_CLOCK_SKEW_SECS,
    RecoverError, domain, epoch_end, epoch_of,
};

/// Dev-dependencies used only by the feature-gated anvil end-to-end test.
///
/// `unused_crate_dependencies` is denied workspace-wide and fires on the unit-test target,
/// where these are linked but unreferenced.
#[cfg(test)]
mod e2e_only_dev_deps {
    use alloy_node_bindings as _;
    use eyre as _;
    use rand as _;
    use tokio as _;
}
