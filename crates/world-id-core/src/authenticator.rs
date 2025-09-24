//! The main Authenticator instance.
//!
//! The Authenticator is the user's entry point to the World ID Protocol.

use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;

/// Authenticator holds an internal Alloy signer.
#[derive(Clone, Debug)]
pub struct Authenticator {
    signer: PrivateKeySigner,
}

impl Authenticator {
    /// Create a new Authenticator from an input seed string.
    ///
    /// The seed is interpreted as a hexadecimal private key string (with or without `0x`).
    ///
    /// # Errors
    /// Will error if the provided decimal is not a valid key.
    pub fn new_from_seed(seed: &str) -> Result<Self> {
        let signer: PrivateKeySigner = seed.parse()?;
        Ok(Self { signer })
    }

    /// Returns a reference to the internal signer.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn signer(&self) -> &PrivateKeySigner {
        &self.signer
    }
}
