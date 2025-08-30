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
    pub fn new_from_seed(seed: &str) -> Result<Self> {
        let signer: PrivateKeySigner = seed.parse()?;
        Ok(Self { signer })
    }

    /// Returns a reference to the internal signer.
    pub fn signer(&self) -> &PrivateKeySigner { &self.signer }
}


