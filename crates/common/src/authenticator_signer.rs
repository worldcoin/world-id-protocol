use alloy::{primitives::B256, signers::local::PrivateKeySigner};
use anyhow::Result;
use eddsa_babyjubjub::EdDSAPrivateKey;

/// Authenticator holds an internal Alloy signer.
#[derive(Clone, Debug)]
pub struct AuthenticatorSigner {
    onchain_signer: PrivateKeySigner,
    offchain_signer: EdDSAPrivateKey,
}

impl AuthenticatorSigner {
    /// Create a new Authenticator from an input seed string.
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self> {
        if seed.len() != 32 {
            return Err(anyhow::anyhow!("seed must be 32 bytes"));
        }
        let bytes: [u8; 32] = seed.try_into()?;
        let onchain_signer = PrivateKeySigner::from_bytes(&bytes.try_into()?)?;
        let offchain_signer = EdDSAPrivateKey::from_bytes(bytes);

        Ok(Self {
            onchain_signer,
            offchain_signer,
        })
    }

    /// Returns a reference to the internal signer.
    pub fn onchain_signer(&self) -> &PrivateKeySigner {
        &self.onchain_signer
    }

    /// Returns a reference to the internal offchain signer.
    pub fn offchain_signer(&self) -> &EdDSAPrivateKey {
        &self.offchain_signer
    }
}
