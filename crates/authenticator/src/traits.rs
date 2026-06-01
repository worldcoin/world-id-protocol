use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use ruint::aliases::U256;
use secrecy::ExposeSecret;
use world_id_primitives::{FieldElement, PrimitiveError, authenticator::ProtocolSigner};

use crate::authenticator::Authenticator;

impl ProtocolSigner for Authenticator {
    fn sign(&self, message: FieldElement) -> EdDSASignature {
        self.signer
            .offchain_signer_private_key()
            .expose_secret()
            .sign(*message)
    }
}

/// A trait for types that can be represented as a `U256` on-chain.
pub trait OnchainKeyRepresentable {
    /// Converts an off-chain public key into a `U256` representation for on-chain use in the `WorldIDRegistry` contract.
    ///
    /// The `U256` representation is a 32-byte little-endian encoding of the **compressed** (single point) public key.
    ///
    /// # Errors
    /// Will error if the public key unexpectedly fails to serialize.
    fn to_ethereum_representation(&self) -> Result<U256, PrimitiveError>;
}

impl OnchainKeyRepresentable for EdDSAPublicKey {
    // REVIEW: updating to BE
    fn to_ethereum_representation(&self) -> Result<U256, PrimitiveError> {
        let mut compressed_bytes = Vec::new();
        self.pk
            .serialize_compressed(&mut compressed_bytes)
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;
        Ok(U256::from_le_slice(&compressed_bytes))
    }
}
