use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use eyre::Result;
use oprf_client::{EdDSAPrivateKey, EdDSAPublicKey};
use secrecy::{ExposeSecret, SecretBox};

/// The inner signer which can sign requests for both on-chain and off-chain operations. Both issuers and authenticators use this.
///
/// Both keys are zeroized on drop.
#[derive(Debug)]
pub struct Signer {
    /// An on-chain `SECP256K1` private key. This key is used to sign operations that are validated on-chain (see `AccountRegistry` or CredentialSchemaIssuerRegistry`).
    onchain_signer: PrivateKeySigner,
    /// An off-chain `EdDSA` private key. This key is used to sign operations that are validated off-chain, primarily within Zero-Knowledge Circuits.
    offchain_signer: SecretBox<EdDSAPrivateKey>,
}

impl Signer {
    /// Initializes a new signer from an input seed.
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self> {
        if seed.len() != 32 {
            return Err(eyre::eyre!("seed must be 32 bytes"));
        }
        let bytes: [u8; 32] = seed.try_into()?;
        let onchain_signer = PrivateKeySigner::from_bytes(&bytes.into())?;
        let offchain_signer = SecretBox::new(Box::new(EdDSAPrivateKey::from_bytes(bytes)));

        Ok(Self {
            onchain_signer,
            offchain_signer,
        })
    }

    /// Returns a reference to the internal signer.
    #[allow(unused)]
    pub const fn onchain_signer(&self) -> &PrivateKeySigner {
        &self.onchain_signer
    }

    /// Returns a reference to the internal offchain signer.
    pub const fn offchain_signer_private_key(&self) -> &SecretBox<EdDSAPrivateKey> {
        &self.offchain_signer
    }

    pub const fn onchain_signer_address(&self) -> Address {
        self.onchain_signer.address()
    }

    pub fn offchain_signer_pubkey(&self) -> EdDSAPublicKey {
        self.offchain_signer.expose_secret().public()
    }
}
