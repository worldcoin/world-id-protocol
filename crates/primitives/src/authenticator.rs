use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use ark_babyjubjub::{EdwardsAffine, Fq};
use ark_ff::AdditiveGroup;
use arrayvec::ArrayVec;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use poseidon2::Poseidon2;
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

    /// Sets a new public key at the given index if it's within bounds of the initialized set.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds.
    pub fn try_set_at_index(
        &mut self,
        index: usize,
        pubkey: EdDSAPublicKey,
    ) -> Result<(), PrimitiveError> {
        if index >= self.len() || index >= MAX_AUTHENTICATOR_KEYS {
            return Err(PrimitiveError::OutOfBounds);
        }
        self.0[index] = pubkey;
        Ok(())
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

    /// Computes the Poseidon2 leaf hash commitment for this key set as stored in the AccountRegistry.
    #[must_use]
    pub fn leaf_hash(&self) -> Fq {
        let poseidon2_16: Poseidon2<Fq, 16, 5> = Poseidon2::default();
        let mut input = [Fq::ZERO; 16];

        input[0] =
            Fq::from_str("105702839725298824521994315").expect("domain separator fits in field");

        let pk_array = self.as_affine_array();
        for i in 0..MAX_AUTHENTICATOR_KEYS {
            input[i * 2 + 1] = pk_array[i].x;
            input[i * 2 + 2] = pk_array[i].y;
        }

        poseidon2_16.permutation(&input)[1]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_pubkey() -> EdDSAPublicKey {
        EdDSAPublicKey {
            pk: EdwardsAffine::default(),
        }
    }

    #[test]
    fn test_try_set_at_index_within_bounds() {
        let mut key_set = AuthenticatorPublicKeySet::new(None).unwrap();
        let pubkey = create_test_pubkey();

        // Setting at index 0 when empty should fail (index >= len)
        let result = key_set.try_set_at_index(0, pubkey.clone());
        assert!(result.is_err(), "Should not panic, should return error");

        // Push a key first
        key_set.try_push(pubkey.clone()).unwrap();

        // Now setting at index 0 should succeed
        key_set.try_set_at_index(0, pubkey).unwrap();
    }

    #[test]
    fn test_try_set_at_index_at_length() {
        let mut key_set = AuthenticatorPublicKeySet::new(None).unwrap();
        let pubkey = create_test_pubkey();

        // Push one key
        key_set.try_push(pubkey.clone()).unwrap();

        // Try to set at index == len (should fail, not panic)
        let result = key_set.try_set_at_index(1, pubkey);
        assert!(result.is_err(), "Should not panic when index equals length");
    }

    #[test]
    fn test_try_set_at_index_out_of_bounds() {
        let mut key_set = AuthenticatorPublicKeySet::new(None).unwrap();
        let pubkey = create_test_pubkey();

        // Try to set at index beyond MAX_AUTHENTICATOR_KEYS
        let result = key_set.try_set_at_index(MAX_AUTHENTICATOR_KEYS, pubkey.clone());
        assert!(
            result.is_err(),
            "Should not panic when index >= MAX_AUTHENTICATOR_KEYS"
        );

        let result = key_set.try_set_at_index(MAX_AUTHENTICATOR_KEYS + 1, pubkey);
        assert!(
            result.is_err(),
            "Should not panic when index > MAX_AUTHENTICATOR_KEYS"
        );
    }

    #[test]
    fn test_try_push_within_capacity() {
        let mut key_set = AuthenticatorPublicKeySet::new(None).unwrap();
        let pubkey = create_test_pubkey();

        // Should be able to push up to MAX_AUTHENTICATOR_KEYS without panicking
        for i in 0..MAX_AUTHENTICATOR_KEYS {
            let result = key_set.try_push(pubkey.clone());
            assert!(
                result.is_ok(),
                "Should not panic when pushing element {} of {}",
                i + 1,
                MAX_AUTHENTICATOR_KEYS
            );
        }

        assert_eq!(key_set.len(), MAX_AUTHENTICATOR_KEYS);

        let result = key_set.try_push(pubkey);
        assert!(result.is_err()); // should return an error because the set is full, but not panic
    }

    #[test]
    fn test_as_affine_array_empty_set() {
        let key_set = AuthenticatorPublicKeySet::new(None).unwrap();
        let array = key_set.as_affine_array();

        // All elements should be default
        assert_eq!(array.len(), MAX_AUTHENTICATOR_KEYS);
        for affine in &array {
            assert_eq!(*affine, EdwardsAffine::default());
        }
    }

    #[test]
    fn test_as_affine_array_partial_set() {
        let mut key_set = AuthenticatorPublicKeySet::new(None).unwrap();
        let pubkey = create_test_pubkey();

        // Add 3 keys
        for _ in 0..3 {
            key_set.try_push(pubkey.clone()).unwrap();
        }

        let array = key_set.as_affine_array();

        // Array should have correct length
        assert_eq!(array.len(), MAX_AUTHENTICATOR_KEYS);

        // First 3 should match the pubkey
        for item in array.iter().take(3) {
            assert_eq!(item, &pubkey.pk);
        }

        for item in array.iter().take(MAX_AUTHENTICATOR_KEYS).skip(3) {
            assert_eq!(item, &EdwardsAffine::default());
        }
    }
}
