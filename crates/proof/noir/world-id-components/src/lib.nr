//! World ID circuit components (WIP-100 §6): World ID Authentication, Credential
//! Verification and Session Commitment, plus the variable-length hash `H_var` (§3.3.3),
//! shared by the World ID circuits.
pub mod authentication;
pub mod constants;
pub mod credential;
pub mod session;
pub mod types;
pub mod var_hash;
pub mod merkle;

mod tests;
