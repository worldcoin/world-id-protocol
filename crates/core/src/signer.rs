use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use secrecy::{ExposeSecret, SecretBox};
use world_id_primitives::PrimitiveError;

/// The inner signer which can sign requests for both on-chain and off-chain operations. Both issuers and authenticators use this.
///
/// Both keys are zeroized on drop.
#[derive(Debug)]
pub struct Signer {
    /// An on-chain `SECP256K1` private key. This key is used to sign operations that are validated on-chain (see `WorldIDRegistry` or `CredentialSchemaIssuerRegistry`).
    onchain_signer: PrivateKeySigner,
    /// An off-chain `EdDSA` private key. This key is used to sign operations that are validated off-chain, primarily within Zero-Knowledge Circuits.
    offchain_signer: SecretBox<EdDSAPrivateKey>,
}

impl Signer {
    /// Initializes a new signer from an input seed.
    ///
    /// # Errors
    /// Returns `PrimitiveError::InvalidInput` if the seed is not exactly 32 bytes.
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self, PrimitiveError> {
        if seed.len() != 32 {
            return Err(PrimitiveError::InvalidInput {
                attribute: "seed".to_string(),
                reason: format!("must be 32 bytes, got {} bytes", seed.len()),
            });
        }
        let bytes: [u8; 32] = seed.try_into().map_err(|_| PrimitiveError::InvalidInput {
            attribute: "seed".to_string(),
            reason: "failed to convert to [u8; 32]".to_string(),
        })?;
        let onchain_signer = PrivateKeySigner::from_bytes(&bytes.into()).map_err(|e| {
            PrimitiveError::InvalidInput {
                attribute: "seed".to_string(),
                reason: format!("invalid private key: {e}"),
            }
        })?;
        let offchain_signer = SecretBox::new(Box::new(EdDSAPrivateKey::from_bytes(bytes)));

        Ok(Self {
            onchain_signer,
            offchain_signer,
        })
    }

    /// Returns a mutable reference to the internal signer.
    #[allow(clippy::missing_const_for_fn)] // requires a mutable
    pub fn onchain_signer(&mut self) -> &mut PrivateKeySigner {
        &mut self.onchain_signer
    }

    /// Returns a reference to the internal offchain signer.
    pub const fn offchain_signer_private_key(&self) -> &SecretBox<EdDSAPrivateKey> {
        &self.offchain_signer
    }

    /// Returns the address of the on-chain signer.
    pub const fn onchain_signer_address(&self) -> Address {
        self.onchain_signer.address()
    }

    /// Returns the public key of the off-chain signer.
    pub fn offchain_signer_pubkey(&self) -> EdDSAPublicKey {
        self.offchain_signer.expose_secret().public()
    }
}
