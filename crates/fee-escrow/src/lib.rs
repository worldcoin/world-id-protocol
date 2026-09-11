//! YABS payment-channel authorisations for World ID proof requests.
//!
//! A relying party opens an escrow channel funded by a `payer`, then attaches a channel id and
//! a lane nonce to each [`ProofRequestV2`]. The RP's `spendKey` signs the pair as EIP-712
//! `PaymentAuthorization` typed data bound to the escrow's domain. A collector verifies that
//! signature, checks the channel can still cover the fee, and later batches the highest
//! authorisation per lane into `IWorldIDFeeEscrow.settle`.
//!
//! ```no_run
//! use alloy::signers::local::PrivateKeySigner;
//! use world_id_fee_escrow::{
//!     nonce::NonceAllocator,
//!     request::ProofRequestV2,
//!     typed_data::{channel_id, domain},
//! };
//!
//! # fn run(inner: world_id_primitives::ProofRequest, spend_key: PrivateKeySigner,
//! #        escrow: alloy_primitives::Address, settings: world_id_fee_escrow::typed_data::ChannelSettings)
//! # -> eyre::Result<()> {
//! let domain = domain(480, escrow);
//! let cid = channel_id(480, escrow, &settings);
//! let mut nonces = NonceAllocator::new(settings.laneCount)?;
//! let request = ProofRequestV2::sign(inner, cid, nonces.next_round_robin()?, &spend_key, &domain)?;
//! request.verify(&domain, settings.spendKey)?;
//! # Ok(()) }
//! ```
//!
//! This is a proof of concept. Both [`nonce::NonceAllocator`] and [`collector::Ledger`] are
//! in-memory and single-process; production use needs durable, serialised state on both sides.

pub mod collector;
pub mod nonce;
pub mod request;
pub mod typed_data;

pub use collector::{AdmitError, ChannelView, Ledger};
pub use nonce::{LaneNonce, NonceAllocator, NonceError};
pub use request::{OnchainPaymentAuthorization, ProofRequestV2, RequestV2Error};
pub use typed_data::{
    ChannelSettings, OpenChannelTypedData, PaymentAuthorizationTypedData, channel_id, domain,
    sign_open_channel,
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
