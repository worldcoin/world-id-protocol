use crate::Signer;
use eyre::Result;

/// Provides base functionality for issuing credentials.
#[derive(Debug)]
pub struct Issuer {
    signer: Signer,
}

impl Issuer {
    pub fn new(seed: &[u8]) -> Result<Self> {
        let signer = Signer::from_seed_bytes(seed)?;
        Ok(Self { signer })
    }
}
