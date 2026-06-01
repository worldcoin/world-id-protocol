mod authenticator;
pub use authenticator::*;

mod error;
pub use error::AuthenticatorError;

mod account;
mod init;
mod prove;
mod recovery;
mod traits;
pub use init::InitializingAuthenticator;
pub use traits::OnchainKeyRepresentable;

pub mod api_types {
    pub use world_id_primitives::api_types::*;
}

mod service_client;

pub mod ohttp;

pub mod proof {
    pub use world_id_proof::*;
}

/// Re-export of all the World ID primitives
pub mod primitives {
    pub use world_id_primitives::*;
}
