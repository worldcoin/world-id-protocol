//! The Rust side of the shared `world-id-components` Noir library: witness encoders for its input
//! types, and the input check of its World ID Authentication component.

use std::collections::BTreeMap;

use ark_ff::{BigInteger as _, PrimeField as _};
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use provekit_common::{InputValue, NoirElement};
use world_id_primitives::{
    AuthenticatorPublicKeySet, MAX_AUTHENTICATOR_KEYS, TREE_DEPTH, merkle::MerkleInclusionProof,
};

use crate::{NoirRepresentable as _, error::ProofInputError, to_noir_element};

/// Encodes a `PublicKey { x, y }`.
pub(crate) fn public_key(point: &ark_babyjubjub::EdwardsAffine) -> InputValue {
    let mut fields = BTreeMap::new();
    fields.insert("x".into(), InputValue::Field(to_noir_element(point.x)));
    fields.insert("y".into(), InputValue::Field(to_noir_element(point.y)));
    InputValue::Struct(fields)
}

/// Encodes a `Signature { s, r }`.
///
/// `s` is a babyjubjub scalar, lifted to the bn254 scalar field via its big-endian bytes.
pub(crate) fn signature(signature: &EdDSASignature) -> InputValue {
    let s = ark_bn254::Fr::from_be_bytes_mod_order(&signature.s.into_bigint().to_bytes_be());
    let mut fields = BTreeMap::new();
    fields.insert("s".into(), InputValue::Field(to_noir_element(s)));
    fields.insert(
        "r".into(),
        InputValue::Vec(vec![
            InputValue::Field(to_noir_element(signature.r.x)),
            InputValue::Field(to_noir_element(signature.r.y)),
        ]),
    );
    InputValue::Struct(fields)
}

/// Encodes the `AccountInputs` of the World ID Authentication component.
pub(crate) fn account_inputs<const MAX_DEPTH: usize>(
    key_set: &AuthenticatorPublicKeySet,
    key_index: u64,
    signature: &EdDSASignature,
    inclusion_proof: &MerkleInclusionProof<MAX_DEPTH>,
) -> InputValue {
    let mut account = BTreeMap::new();
    account.insert(
        "user_pk".into(),
        InputValue::Vec(key_set.as_affine_array().iter().map(public_key).collect()),
    );
    account.insert(
        "pk_index".into(),
        InputValue::Field(NoirElement::from(key_index)),
    );
    account.insert("sig".into(), self::signature(signature));
    account.insert(
        "leaf_index".into(),
        InputValue::Field(NoirElement::from(inclusion_proof.leaf_index)),
    );
    account.insert(
        "siblings".into(),
        InputValue::Vec(
            inclusion_proof
                .siblings
                .iter()
                .map(|sibling| (*sibling).into_noir_value())
                .collect(),
        ),
    );
    InputValue::Struct(account)
}

/// Checks the account inputs of the World ID Authentication component the way the circuit does,
/// and returns the authenticator key that must have signed the circuit's message.
///
/// # Errors
/// Returns a [`ProofInputError`] if the leaf index, key index or inclusion proof is invalid.
pub(crate) fn check_account_input_validity<'a, const MAX_DEPTH: usize>(
    key_set: &'a AuthenticatorPublicKeySet,
    key_index: u64,
    inclusion_proof: &MerkleInclusionProof<MAX_DEPTH>,
) -> Result<&'a EdDSAPublicKey, ProofInputError> {
    // The circuit requires `0 < leaf_index < 2^30`; leaf `0` is reserved in the `WorldIDRegistry`.
    let leaf_index = inclusion_proof.leaf_index;
    if leaf_index == 0 {
        return Err(ProofInputError::ValueMustNotBeZero { name: "leaf_index" });
    }
    if leaf_index >= 1 << TREE_DEPTH {
        return Err(ProofInputError::ValueOutOfBounds {
            name: "leaf_index",
            is: leaf_index.into(),
            limit: (1u64 << TREE_DEPTH).into(),
        });
    }

    if key_index >= MAX_AUTHENTICATOR_KEYS as u64 {
        return Err(ProofInputError::ValueOutOfBounds {
            name: "key_index",
            is: key_index.into(),
            limit: (MAX_AUTHENTICATOR_KEYS as u64).into(),
        });
    }
    let key = usize::try_from(key_index)
        .ok()
        .and_then(|index| key_set.get(index))
        .ok_or(ProofInputError::InactiveAuthenticatorKey { index: key_index })?;
    if !inclusion_proof.is_valid(key_set.leaf_hash().into()) {
        return Err(ProofInputError::InvalidMerkleTreeInclusionProof);
    }
    Ok(key)
}
