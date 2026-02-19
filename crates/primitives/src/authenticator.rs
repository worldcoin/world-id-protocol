use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use ark_babyjubjub::{EdwardsAffine, Fq};
use ark_ff::{AdditiveGroup, PrimeField as _};
use arrayvec::ArrayVec;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{FieldElement, PrimitiveError};

/// The maximum number of authenticator public keys that can be registered at any time
/// per World ID Account.
///
/// This constrained is introduced to maintain proof performance reasonable even
/// in devices with limited resources.
pub const MAX_AUTHENTICATOR_KEYS: usize = 7;

/// Errors for decoding sparse authenticator pubkey slots.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SparseAuthenticatorPubkeysError {
    /// The input contains a non-empty slot index outside supported bounds.
    #[error(
        "invalid authenticator pubkey slot {slot_index}; max supported slot is {max_supported_slot}"
    )]
    SlotOutOfBounds {
        /// Slot index returned by the source.
        slot_index: usize,
        /// Highest supported slot index.
        max_supported_slot: usize,
    },
    /// A slot contained bytes that are not a valid compressed public key.
    #[error("invalid authenticator public key at slot {slot_index}: {reason}")]
    InvalidCompressedPubkey {
        /// Slot index of the invalid entry.
        slot_index: usize,
        /// Parse error details.
        reason: String,
    },
}

/// Domain separator for the authenticator OPRF query digest.
const OPRF_QUERY_DS: &[u8] = b"World ID Query";

/// Computes the Poseidon2 digest for an authenticator OPRF query.
///
/// # Arguments
/// * `leaf_index` - The leaf index of the authenticator in the World ID Registry.
/// * `action` - The action field element.
/// * `query_origin_id` - The `RpId` or `issuer_schema_id`.
#[must_use]
pub fn oprf_query_digest(
    leaf_index: u64,
    action: FieldElement,
    query_origin_id: FieldElement,
) -> FieldElement {
    let input = [
        ark_babyjubjub::Fq::from_be_bytes_mod_order(OPRF_QUERY_DS),
        leaf_index.into(),
        *query_origin_id,
        *action,
    ];
    poseidon2::bn254::t4::permutation(&input)[1].into()
}

/// Decodes sparse authenticator pubkey slots while preserving slot positions.
///
/// Input may contain `None` entries for removed authenticators. Trailing empty slots are trimmed,
/// interior holes are preserved as default affine points, and used slots beyond
/// [`MAX_AUTHENTICATOR_KEYS`] are rejected.
///
/// # Errors
/// Returns [`SparseAuthenticatorPubkeysError`] if a used slot is out of bounds or any compressed
/// key bytes are invalid.
pub fn decode_sparse_authenticator_pubkeys(
    pubkeys: Vec<Option<U256>>,
) -> Result<AuthenticatorPublicKeySet, SparseAuthenticatorPubkeysError> {
    let last_present_idx = pubkeys.iter().rposition(Option::is_some);
    if let Some(idx) = last_present_idx
        && idx >= MAX_AUTHENTICATOR_KEYS
    {
        return Err(SparseAuthenticatorPubkeysError::SlotOutOfBounds {
            slot_index: idx,
            max_supported_slot: MAX_AUTHENTICATOR_KEYS - 1,
        });
    }

    let normalized_len = last_present_idx.map_or(0, |idx| idx + 1);
    let decoded_pubkeys = pubkeys
        .into_iter()
        .take(normalized_len)
        .enumerate()
        .map(|(idx, pubkey)| match pubkey {
            Some(pubkey) => EdDSAPublicKey::from_compressed_bytes(pubkey.to_le_bytes())
                .map(Some)
                .map_err(
                    |e| SparseAuthenticatorPubkeysError::InvalidCompressedPubkey {
                        slot_index: idx,
                        reason: e.to_string(),
                    },
                ),
            None => Ok(None),
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(AuthenticatorPublicKeySet(
        decoded_pubkeys
            .into_iter()
            .collect::<ArrayVec<_, MAX_AUTHENTICATOR_KEYS>>(),
    ))
}

/// A set of **off-chain** authenticator public keys for a World ID Account.
///
/// Each World ID Account has a number of public keys for each authorized authenticator;
/// a commitment to the entire set of public keys is stored in the `WorldIDRegistry` contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorPublicKeySet(ArrayVec<Option<EdDSAPublicKey>, MAX_AUTHENTICATOR_KEYS>);

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
                    .map(Some)
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
            array[i] = pubkey
                .as_ref()
                .map_or_else(EdwardsAffine::default, |pubkey| pubkey.pk);
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
        self.0.get(index).and_then(Option::as_ref)
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
        self.0[index] = Some(pubkey);
        Ok(())
    }

    /// Clears the public key at the given index while preserving slot position.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds.
    pub fn try_clear_at_index(&mut self, index: usize) -> Result<(), PrimitiveError> {
        if index >= self.len() || index >= MAX_AUTHENTICATOR_KEYS {
            return Err(PrimitiveError::OutOfBounds);
        }
        self.0[index] = None;
        Ok(())
    }

    /// Pushes a new public key onto the set.
    ///
    /// # Errors
    /// Returns an error if the set is full.
    pub fn try_push(&mut self, pubkey: EdDSAPublicKey) -> Result<(), PrimitiveError> {
        self.0
            .try_push(Some(pubkey))
            .map_err(|_| PrimitiveError::OutOfBounds)
    }

    /// Computes the Poseidon2 leaf hash commitment for this key set as stored in the `WorldIDRegistry`.
    ///
    /// # Panics
    /// Panics if the domain separator constant cannot be converted into an `Fq`.
    #[must_use]
    pub fn leaf_hash(&self) -> Fq {
        let mut input = [Fq::ZERO; 16];

        input[0] =
            Fq::from_str("105702839725298824521994315").expect("domain separator fits in field");

        let pk_array = self.as_affine_array();
        for i in 0..MAX_AUTHENTICATOR_KEYS {
            input[i * 2 + 1] = pk_array[i].x;
            input[i * 2 + 2] = pk_array[i].y;
        }

        poseidon2::bn254::t16::permutation(&input)[1]
    }
}

impl Deref for AuthenticatorPublicKeySet {
    type Target = ArrayVec<Option<EdDSAPublicKey>, MAX_AUTHENTICATOR_KEYS>;
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
    use crate::Signer;
    use ark_serialize::CanonicalSerialize as _;

    fn create_test_pubkey() -> EdDSAPublicKey {
        EdDSAPublicKey {
            pk: EdwardsAffine::default(),
        }
    }

    fn test_pubkey(seed_byte: u8) -> EdDSAPublicKey {
        Signer::from_seed_bytes(&[seed_byte; 32])
            .unwrap()
            .offchain_signer_pubkey()
    }

    fn encoded_test_pubkey(seed_byte: u8) -> U256 {
        let mut compressed = Vec::new();
        test_pubkey(seed_byte)
            .pk
            .serialize_compressed(&mut compressed)
            .unwrap();
        U256::from_le_slice(&compressed)
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

    #[test]
    fn test_decode_sparse_pubkeys_trims_trailing_empty_slots() {
        let mut encoded_pubkeys = vec![Some(encoded_test_pubkey(1)), Some(encoded_test_pubkey(2))];
        encoded_pubkeys.extend(vec![None; MAX_AUTHENTICATOR_KEYS + 5]);

        let key_set = decode_sparse_authenticator_pubkeys(encoded_pubkeys).unwrap();

        assert_eq!(key_set.len(), 2);
        assert_eq!(key_set[0].as_ref().unwrap().pk, test_pubkey(1).pk);
        assert_eq!(key_set[1].as_ref().unwrap().pk, test_pubkey(2).pk);
    }

    #[test]
    fn test_decode_sparse_pubkeys_preserves_interior_holes() {
        let key_set = decode_sparse_authenticator_pubkeys(vec![
            Some(encoded_test_pubkey(1)),
            None,
            Some(encoded_test_pubkey(2)),
        ])
        .unwrap();

        assert_eq!(key_set.len(), 3);
        assert_eq!(key_set[0].as_ref().unwrap().pk, test_pubkey(1).pk);
        assert_eq!(key_set[1], None);
        assert_eq!(key_set[2].as_ref().unwrap().pk, test_pubkey(2).pk);
    }

    #[test]
    fn test_decode_sparse_pubkeys_rejects_used_slot_beyond_max() {
        let mut encoded_pubkeys = vec![None; MAX_AUTHENTICATOR_KEYS + 1];
        encoded_pubkeys[MAX_AUTHENTICATOR_KEYS] = Some(encoded_test_pubkey(1));

        let error = decode_sparse_authenticator_pubkeys(encoded_pubkeys).unwrap_err();
        assert!(matches!(
            error,
            SparseAuthenticatorPubkeysError::SlotOutOfBounds {
                slot_index,
                max_supported_slot
            } if slot_index == MAX_AUTHENTICATOR_KEYS && max_supported_slot == MAX_AUTHENTICATOR_KEYS - 1
        ));
    }
}
