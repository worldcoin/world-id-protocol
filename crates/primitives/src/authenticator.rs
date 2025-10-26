use alloy::primitives::Address;
use ark_babyjubjub::EdwardsAffine;
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{FieldElement, TypeError};

/// The maximum number of authenticator public keys that can be registered at any time
/// per World ID Account.
///
/// This constrained is introduced to maintain proof performance reasonable even
/// in devices with limited resources.
pub const MAX_AUTHENTICATOR_KEYS: usize = 7;

/// A set of **off-chain** authenticator public keys for a World ID Account.
///
/// Each World ID Account has a number of public keys for each authorized authenticator;
/// a commitment to the entire set of public keys is stored in the `AccountRegistry` contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorPublicKeySet(pub [EdDSAPublicKey; MAX_AUTHENTICATOR_KEYS]);

impl AuthenticatorPublicKeySet {
    /// Converts the set of public keys to a set of field elements where
    /// each item is the x and y coordinates of the public key as a pair.
    #[must_use]
    pub fn to_field_elements(self) -> [[FieldElement; 2]; MAX_AUTHENTICATOR_KEYS] {
        self.0.map(|k| [k.pk.x.into(), k.pk.y.into()])
    }

    /// Returns the public key at a specific index as a single compressed point.
    ///
    /// # Errors
    /// Will error if the public key cannot be serialized.
    pub fn compressed_point_at_index(&self, index: usize) -> Result<U256, TypeError> {
        let pk = self.0[index].pk;
        let mut compressed_bytes = Vec::new();
        pk.serialize_compressed(&mut compressed_bytes)
            .map_err(|_| {
                TypeError::Serialization("unexpected error serializing affine point".to_string())
            })?;
        Ok(U256::from_le_slice(&compressed_bytes))
    }

    /// Sets the key at the given index.
    ///
    /// # Errors
    /// Will error if the index is out of bounds.
    pub const fn set_key(mut self, index: usize, key: EdDSAPublicKey) -> Result<Self, TypeError> {
        if index >= MAX_AUTHENTICATOR_KEYS {
            return Err(TypeError::OutOfBounds);
        }
        self.0[index] = key;
        Ok(self)
    }
}

impl Default for AuthenticatorPublicKeySet {
    fn default() -> Self {
        let default_key = EdDSAPublicKey {
            pk: EdwardsAffine::default(),
        };
        // TODO: Implement Copy trait for EdDSAPublicKey
        let keys = core::array::from_fn(|_| default_key.clone());
        Self(keys)
    }
}

/// Enables entities that sign messages within the Protocol for use with the ZK circuits.
///
/// This is in particular used by Authenticators to authorize requests for nullifier generation.
pub trait ProtocolSigner {
    /// Signs a message with the protocol signer using the `EdDSA` scheme (**off-chain** signer), for use
    /// with the Protocol ZK circuits.
    fn sign(&self, message: FieldElement) -> EdDSASignature
    where
        Self: Sized + Send + Sync;
}

/// Registers a new World ID Account in the Protocol.
///
/// - HTTP request from an `authenticator` to the `gateway`.
/// - Results in a `AccountRegistry::createAccount` call on-chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    /// The address which is authorized to recover the account on behalf of the user.
    /// This can be set to `None` to disable recovery.
    pub recovery_address: Option<Address>,
    /// The list of all authorized on-chain signers to perform management operations on the account.
    pub authenticator_addresses: Vec<Address>,
    /// The list of all authorized off-chain signers which can generate proofs on behalf of the user;
    /// this list is indexed on the `indexer` for accessibility but committed to on-chain.
    pub authenticator_pubkeys: AuthenticatorPublicKeySet,
    /// A commitment to the `authenticator_pubkeys[]` which is recorded on-chain.
    pub offchain_signer_commitment: U256,
}

/// The request to update an authenticator.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAuthenticatorRequest {
    /// The account index.
    pub account_index: U256,
    /// The old authenticator address.
    pub old_authenticator_address: Address,
    /// The new authenticator address.
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The nonce.
    pub nonce: U256,
    /// The pubkey id.
    pub pubkey_id: Option<U256>,
    /// The new authenticator pubkey.
    pub new_authenticator_pubkey: Option<U256>,
}

/// The request to insert an authenticator.
#[derive(Debug, Serialize, Deserialize)]
pub struct InsertAuthenticatorRequest {
    /// The account index.
    pub account_index: U256,
    /// The new authenticator address.
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The nonce.
    pub nonce: U256,
    /// The pubkey id.
    pub pubkey_id: U256,
    /// The new authenticator pubkey.
    pub new_authenticator_pubkey: U256,
}

/// The request to remove an authenticator.
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveAuthenticatorRequest {
    /// The account index.
    pub account_index: U256,
    /// The authenticator address.
    pub authenticator_address: Address,
    /// The old offchain signer commitment.
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The nonce.
    pub nonce: U256,
    /// The pubkey id.
    pub pubkey_id: Option<U256>,
    /// The authenticator pubkey.
    pub authenticator_pubkey: Option<U256>,
}

/// The request to recover an account.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverAccountRequest {
    /// The account index.
    pub account_index: U256,
    /// The new authenticator address.
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The nonce.
    pub nonce: U256,
    /// The new authenticator pubkey.
    pub new_authenticator_pubkey: Option<U256>,
}
