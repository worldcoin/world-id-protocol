//! Request/response models for the proof request protocol. This module includes the
//! data structures for requests and responses, action encoding utilities, and
//! constraint evaluation helpers.

/// Action encoding/decoding helpers and hashing utilities
pub mod action;
/// Constraint data structures and evaluation helpers
pub mod constraints;
/// Request/response model types and validation helpers
pub mod model;

pub use action::Action;
pub use constraints::{ConstraintExpr, ConstraintKind, ConstraintNode};
pub use model::{
    AuthenticatorRequest, AuthenticatorResponse, CredentialRequest, ResponseItem, ValidationError,
};
