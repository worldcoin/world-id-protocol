//! The core library for the World ID Protocol.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod authenticator;
pub use authenticator::Authenticator;

pub mod authenticator_registry;

mod credential;
pub use credential::{Claims, Credential};

pub mod primitives;
