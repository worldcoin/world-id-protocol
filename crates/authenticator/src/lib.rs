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

pub mod registry;
pub use registry::{
    WorldIdRegistry, domain, sign_cancel_recovery_agent_update,
    sign_initiate_recovery_agent_update, sign_insert_authenticator, sign_recover_account,
    sign_remove_authenticator, sign_update_authenticator,
};

pub mod proof {
    pub use world_id_proof::*;
}

/// Re-export of all the World ID primitives
pub mod primitives {
    pub use world_id_primitives::*;
}
