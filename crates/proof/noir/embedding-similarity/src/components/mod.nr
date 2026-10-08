//! World ID circuit components (WIP-113): World ID Authentication, Credential
//! Verification and Session Commitment. Nothing here depends on WIP-202, so the module
//! moves unchanged into a shared library once WIP-113 lands.
pub mod authentication;
pub mod constants;
pub mod credential;
pub mod session;
pub mod types;
pub(crate) mod merkle;
