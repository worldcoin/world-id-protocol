use std::ops::{Deref, DerefMut};

use ark_babyjubjub::EdwardsAffine;
use arrayvec::ArrayVec;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use serde::{Deserialize, Serialize};

use crate::{FieldElement, PrimitiveError};

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
pub struct AuthenticatorPublicKeySet(ArrayVec<EdDSAPublicKey, MAX_AUTHENTICATOR_KEYS>);

impl AuthenticatorPublicKeySet {
    /// Creates a new authenticator public key set with the provided public keys or defaults to none.
    ///
    /// # Errors
    /// Returns an error if the number of public keys exceeds [`MAX_AUTHENTICATOR_KEYS`].
    pub fn new(pubkeys: Option<Vec<EdDSAPublicKey>>) -> Result<Self, PrimitiveError> {
        if let Some(pubkeys) = pubkeys {
            if pubkeys.len() > MAX_AUTHENTICATOR_KEYS {
                return Err(PrimitiveError::OutOfBounds);
            }

            Ok(Self(
                pubkeys
                    .into_iter()
                    .collect::<ArrayVec<_, MAX_AUTHENTICATOR_KEYS>>(),
            ))
        } else {
            Ok(Self(ArrayVec::new()))
        }
    }

    /// Converts the set of public keys to a fixed-length array of Affine points.
    ///
    /// This is usually used to serialize to the circuit input which expects defaulted Affine points for unused slots.
    pub fn as_affine_array(&self) -> [EdwardsAffine; MAX_AUTHENTICATOR_KEYS] {
        let mut array = [EdwardsAffine::default(); MAX_AUTHENTICATOR_KEYS];
        for (i, pubkey) in self.0.iter().enumerate() {
            array[i] = pubkey.pk;
        }
        array
    }

    /// Returns the number of public keys in the set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the public key at the given index.
    ///
    /// It will return `None` if the index is out of bounds, even if it's less than `MAX_AUTHENTICATOR_KEYS` but
    /// the key is not initialized.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&EdDSAPublicKey> {
        self.0.get(index)
    }

    /// Inserts a new public key at the given index.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds.
    pub fn try_insert(
        &mut self,
        index: usize,
        pubkey: EdDSAPublicKey,
    ) -> Result<(), PrimitiveError> {
        self.0
            .try_insert(index, pubkey)
            .map_err(|_| PrimitiveError::OutOfBounds)
    }

    /// Pushes a new public key onto the set.
    ///
    /// # Errors
    /// Returns an error if the set is full.
    pub fn try_push(&mut self, pubkey: EdDSAPublicKey) -> Result<(), PrimitiveError> {
        self.0
            .try_push(pubkey)
            .map_err(|_| PrimitiveError::OutOfBounds)
    }
}

impl Deref for AuthenticatorPublicKeySet {
    type Target = ArrayVec<EdDSAPublicKey, MAX_AUTHENTICATOR_KEYS>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AuthenticatorPublicKeySet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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
