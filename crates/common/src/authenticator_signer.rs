use alloy::{
    primitives::{Address, B256},
    signers::local::PrivateKeySigner,
};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use eyre::Result;

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
            return Err(eyre::eyre!("seed must be 32 bytes"));
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

    pub fn offchain_signer_private_key(&self) -> &EdDSAPrivateKey {
        &self.offchain_signer
    }

    pub fn onchain_signer_address(&self) -> Address {
        self.onchain_signer.address()
    }

    pub fn offchain_signer_pubkey(&self) -> EdDSAPublicKey {
        self.offchain_signer.public()
    }
}
