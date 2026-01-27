//! Circuit input types for the World ID Protocol circuits.
//!
//! This module requires the `circuits` feature and is not available in WASM builds.

use std::collections::HashMap;

use ark_ff::{PrimeField, Zero};
use eddsa_babyjubjub::EdDSAPublicKey;
use groth16_material::circom::ProofInput;
use poseidon2::Poseidon2;
use ruint::aliases::U256;

use crate::{
    FieldElement,
    authenticator::{AuthenticatorPublicKeySet, MAX_AUTHENTICATOR_KEYS},
    merkle::MerkleInclusionProof,
};

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

#[inline]
pub(crate) fn fq_to_u256_vec(f: ark_babyjubjub::Fq) -> Vec<U256> {
    vec![f.into()]
}

#[inline]
pub(crate) fn fq_seq_to_u256_vec(fs: &[ark_babyjubjub::Fq]) -> Vec<U256> {
    fs.iter().copied().map(Into::into).collect()
}

#[inline]
pub(crate) fn fr_to_u256_vec(f: ark_babyjubjub::Fr) -> Vec<U256> {
    vec![f.into()]
}

#[inline]
pub(crate) fn affine_to_u256_vec(p: ark_babyjubjub::EdwardsAffine) -> Vec<U256> {
    vec![p.x.into(), p.y.into()]
}

#[inline]
pub(crate) fn affine_seq_to_u256_vec(ps: &[ark_babyjubjub::EdwardsAffine]) -> Vec<U256> {
    ps.iter()
        .copied()
        .flat_map(|p| [p.x.into(), p.y.into()])
        .collect()
}

/// The input for the circuit of the OPRF Query Proof `π1`.
///
/// TODO: Rename attribute names to match the `Credential` type.
#[derive(Debug, Clone)]
pub struct QueryProofCircuitInput<const MAX_DEPTH: usize> {
    /// The `AuthenticatorPublicKeySet` represented as an array of Affine points.
    pub pk: [Affine; MAX_AUTHENTICATOR_KEYS],
    /// The index of the public key which will be used to sign the OPRF query from the `AuthenticatorPublicKeySet`.
    pub pk_index: BaseField,
    /// The `s` part of the signature of the query with the public key at the `pk_index`.
    pub s: ScalarField,
    /// The `r` part of the signature of the query with the public key at the `pk_index`.
    pub r: Affine,
    /// The root of the Merkle tree of the `WorldIDRegistry` contract.
    pub merkle_root: BaseField,
    /// The depth of the Merkle tree of the `WorldIDRegistry` contract.
    pub depth: BaseField,
    /// The leaf index of the World ID in the Merkle tree of the `WorldIDRegistry` contract.
    ///
    /// In the `MerkleInclusionProof` type, this is the `leaf_index` field.
    pub mt_index: BaseField,
    /// The siblings of the Merkle proof of the account in the `WorldIDRegistry` contract.
    pub siblings: [BaseField; MAX_DEPTH],
    /// The (non-inverted) blinding factor of the OPRF query.
    pub beta: ScalarField,
    /// The ID of the RP requesting the proof as registered in the `RpRegistry` contract.
    ///
    /// TODO: Will require updates once the new `RpRegistry` is launched.
    pub rp_id: BaseField,
    /// The action for the proof request. See `SingleProofInput` for more details.
    pub action: BaseField,
    /// The nonce of the proof request. See `SingleProofInput` for more details.
    pub nonce: BaseField,
}

#[derive(Debug, thiserror::Error)]
/// Errors that can occur when validating the inputs for a single World ID proof.
pub enum ProofInputError {
    /// The specified Merkle tree depth is invalid.
    #[error("The specified Merkle tree depth is invalid (expected: {expected}, got: {is}).")]
    InvalidMerkleTreeDepth {
        /// Expected depth.
        expected: usize,
        /// Actual depth.
        is: BaseField,
    },
    /// The set of authenticator public keys is invalid.
    #[error("The set of authenticator public keys is invalid.")]
    InvalidAuthenticatorPublicKeySet,
    /// The Merkle Tree index is out of bounds.
    #[error("The Merkle Tree index is out of bounds (got: {is}, max: 2^{depth}).")]
    InvalidMerkleTreeIndex {
        /// Actual index.
        is: BaseField,
        /// Tree depth.
        depth: usize,
    },
    /// The provided Merkle tree inclusion proof is invalid.
    #[error("The provided Merkle tree inclusion proof is invalid.")]
    InvalidMerkleTreeInclusionProof,
    /// The signature over the nonce and RP ID is invalid.
    #[error("The signature over the nonce and RP ID is invalid.")]
    InvalidSignature,
    /// The provided Authenticator public key index is invalid.
    #[error(
        "The provided authenticator public key index is out of bounds (got: {is}, len: {len})."
    )]
    AuthenticatorPublicKeyIndexOutOfBounds {
        /// Actual index.
        is: BaseField,
        /// Length of PK array.
        len: usize,
    },
    /// The provided blinding factor is invalid.
    #[error("The provided blinding factor is invalid.")]
    InvalidBlindingFactor,
}

impl<const TREE_DEPTH: usize> QueryProofCircuitInput<TREE_DEPTH> {
    /// This method checks the validity of the input parameters by emulating the operations that are proved in ZK and raising Errors that would result in an invalid proof.
    pub fn check_input_validity(&self) -> Result<(), ProofInputError> {
        // 1. Check that the depth is within bounds.
        if self.depth != BaseField::new((TREE_DEPTH as u64).into()) {
            return Err(ProofInputError::InvalidMerkleTreeDepth {
                expected: TREE_DEPTH,
                is: self.depth,
            });
        }
        // 2. Check the merkle proof is valid
        // Check the Merkle tree idx is valid.
        let idx_u64 = u64::try_from(FieldElement(self.mt_index)).map_err(|_| {
            ProofInputError::InvalidMerkleTreeIndex {
                is: self.mt_index,
                depth: TREE_DEPTH,
            }
        })?;
        if idx_u64 >= (1u64 << TREE_DEPTH) {
            return Err(ProofInputError::InvalidMerkleTreeIndex {
                is: self.mt_index,
                depth: TREE_DEPTH,
            });
        }

        // Build the leaf from the PKs.
        let pk_set = AuthenticatorPublicKeySet::new(Some(
            self.pk.iter().map(|&x| EdDSAPublicKey { pk: x }).collect(),
        ))
        .map_err(|_| ProofInputError::InvalidAuthenticatorPublicKeySet)?;
        let pk_set_hash = pk_set.leaf_hash();
        let merkle_tree_inclusion_proof = MerkleInclusionProof::new(
            FieldElement(self.merkle_root),
            idx_u64,
            self.siblings.map(FieldElement),
        );
        if !merkle_tree_inclusion_proof.is_valid(FieldElement(pk_set_hash)) {
            return Err(ProofInputError::InvalidMerkleTreeInclusionProof);
        }

        // 3. Check that the signature is valid.
        let pk_index_usize = usize::try_from(FieldElement(self.pk_index)).map_err(|_| {
            ProofInputError::AuthenticatorPublicKeyIndexOutOfBounds {
                is: self.pk_index,
                len: MAX_AUTHENTICATOR_KEYS,
            }
        })?;
        let pk = pk_set.get(pk_index_usize).ok_or(
            ProofInputError::AuthenticatorPublicKeyIndexOutOfBounds {
                is: self.pk_index,
                len: MAX_AUTHENTICATOR_KEYS,
            },
        )?;

        /// Helper function to compute the query hash for a given account, RP ID, and action.
        /// Copied from core for now, since it would introduce a circular dependency to import it.
        fn query_hash(
            leaf_index: u64,
            rp_id: FieldElement,
            action: FieldElement,
        ) -> ark_babyjubjub::Fq {
            const OPRF_QUERY_DS: &[u8] = b"World ID Query";
            let input = [
                ark_babyjubjub::Fq::from_be_bytes_mod_order(OPRF_QUERY_DS),
                leaf_index.into(),
                *FieldElement::from(rp_id),
                *action,
            ];
            let poseidon2_4: Poseidon2<ark_babyjubjub::Fq, 4, 5> = Poseidon2::default();
            poseidon2_4.permutation(&input)[1]
        }

        let query = query_hash(idx_u64, FieldElement(self.rp_id), FieldElement(self.action));
        let signature = eddsa_babyjubjub::EdDSASignature {
            r: self.r,
            s: self.s,
        };

        if !pk.verify(query, &signature) {
            return Err(ProofInputError::InvalidSignature);
        }

        if self.beta.is_zero() {
            return Err(ProofInputError::InvalidBlindingFactor);
        }

        Ok(())
    }
}

impl<const MAX_DEPTH: usize> ProofInput for QueryProofCircuitInput<MAX_DEPTH> {
    fn prepare_input(&self) -> HashMap<String, Vec<U256>> {
        let mut map = HashMap::new();
        map.insert("pk".to_owned(), affine_seq_to_u256_vec(&self.pk));
        map.insert("pk_index".to_owned(), fq_to_u256_vec(self.pk_index));
        map.insert("s".to_owned(), fr_to_u256_vec(self.s));
        map.insert("r".to_owned(), affine_to_u256_vec(self.r));
        map.insert("merkle_root".to_owned(), fq_to_u256_vec(self.merkle_root));
        map.insert("depth".to_owned(), fq_to_u256_vec(self.depth));
        map.insert("mt_index".to_owned(), fq_to_u256_vec(self.mt_index));
        map.insert("siblings".to_owned(), fq_seq_to_u256_vec(&self.siblings));
        map.insert("beta".to_owned(), fr_to_u256_vec(self.beta));
        map.insert("rp_id".to_owned(), fq_to_u256_vec(self.rp_id));
        map.insert("action".to_owned(), fq_to_u256_vec(self.action));
        map.insert("nonce".to_owned(), fq_to_u256_vec(self.nonce));
        map
    }
}

/// The input for the circuit of the Uniqueness Proof `π2` (internally also nullifier proof).
///
/// Externally, the Nullifier Proof is exposed to RPs as a Uniqueness Proof or a Session Proof respectively.
#[derive(Debug, Clone)]
pub struct NullifierProofCircuitInput<const MAX_DEPTH: usize> {
    /// The input for the circuit of the OPRF Query Proof from which this nullifier proof is constructed.
    pub query_input: QueryProofCircuitInput<MAX_DEPTH>,

    // SECTION: Credential Inputs
    /// The id as registered in the `CredentialSchemaIssuerRegistry` representing the (issuer, schema) pair.
    ///
    /// This is the `issuer_schema_id` field of the `Credential` type.
    pub issuer_schema_id: BaseField,
    /// The public key of the issuer of the credential. This is stored in the `Credential` type in the `issuer` field.
    pub cred_pk: Affine,
    /// A specific commitment to particular claims of the `Credential`. In particular:
    /// [`claims_hash`, `associated_data_hash`]
    pub cred_hashes: [BaseField; 2],
    /// The `genesis_issued_at` attribute of the `Credential`. See the `Credential` type for more details.
    pub cred_genesis_issued_at: BaseField,
    /// The `expires_at` attribute of the `Credential`. See the `Credential` type for more details.
    pub cred_expires_at: BaseField,
    /// The `s` part of the signature of the credential (signed by the issuer)
    pub cred_s: ScalarField,
    /// The `r` part of the signature of the credential (signed by the issuer)
    pub cred_r: Affine,
    /// The timestamp from the request.
    pub current_timestamp: BaseField,
    /// The `genesis_issued_at_min` attribute of the `Credential`. See the `Credential` type for more details.
    pub cred_genesis_issued_at_min: BaseField,
    /// The `cred_user_id_r` blinding factor used to generate the `sub`.
    pub cred_sub_blinding_factor: BaseField,
    /// The unique identifier of the `Credential`.
    pub cred_id: BaseField,

    // SECTION: User Inputs
    /// The random commitment for future session proofs generated by the Authenticator.
    ///
    /// TODO: Rename to match new terms and avoid confusion with World ID <3.0's `identity_commitment`.
    pub id_commitment_r: BaseField,

    /// The identity commitment for future session proofs.
    ///
    /// Is used internally to check for equality against the computed identity commitment.
    /// If set to 0, all computed identity commitments will be accepted.
    pub id_commitment: BaseField,

    // SECTION: OPRF Inputs
    /// The `e` part of the `DLog` equality proof (Fiat-Shamir challenge)
    pub dlog_e: BaseField,
    /// The `s` part of the `DLog` equality proof (proof response)
    pub dlog_s: ScalarField,
    /// The public key of the OPRF Nodes for the particular RP (this is the `RpNullifierKey`).
    pub oprf_pk: Affine,
    /// The combined blinded response after aggregating peer commitments from the OPRF nodes.
    pub oprf_response_blinded: Affine,
    /// The unblinded response from from the OPRF nodes.
    pub oprf_response: Affine,

    // SECTION: RP Inputs
    /// The hashed signal provided by the RP and committed to by the user. See `SingleProofInput` for more details.
    pub signal_hash: BaseField,
}

impl<const MAX_DEPTH: usize> ProofInput for NullifierProofCircuitInput<MAX_DEPTH> {
    fn prepare_input(&self) -> std::collections::HashMap<String, Vec<ruint::aliases::U256>> {
        let mut map = self.query_input.prepare_input();
        map.insert(
            "issuer_schema_id".to_owned(),
            fq_to_u256_vec(self.issuer_schema_id),
        );
        map.insert("cred_pk".to_owned(), affine_to_u256_vec(self.cred_pk));
        map.insert(
            "cred_hashes".to_owned(),
            fq_seq_to_u256_vec(&self.cred_hashes),
        );
        map.insert(
            "cred_genesis_issued_at".to_owned(),
            fq_to_u256_vec(self.cred_genesis_issued_at),
        );
        map.insert(
            "cred_genesis_issued_at_min".to_owned(),
            fq_to_u256_vec(self.cred_genesis_issued_at_min),
        );
        map.insert(
            "cred_expires_at".to_owned(),
            fq_to_u256_vec(self.cred_expires_at),
        );
        map.insert("cred_id".to_owned(), fq_to_u256_vec(self.cred_id));
        map.insert(
            "cred_user_id_r".to_owned(),
            fq_to_u256_vec(self.cred_sub_blinding_factor),
        );
        map.insert("cred_s".to_owned(), fr_to_u256_vec(self.cred_s));
        map.insert("cred_r".to_owned(), affine_to_u256_vec(self.cred_r));

        map.insert(
            "id_commitment_r".to_owned(),
            fq_to_u256_vec(self.id_commitment_r),
        );
        map.insert(
            "id_commitment".to_owned(),
            fq_to_u256_vec(self.id_commitment),
        );

        map.insert("dlog_e".to_owned(), fq_to_u256_vec(self.dlog_e));
        map.insert("dlog_s".to_owned(), fr_to_u256_vec(self.dlog_s));
        map.insert("oprf_pk".to_owned(), affine_to_u256_vec(self.oprf_pk));
        map.insert(
            "oprf_response_blinded".to_owned(),
            affine_to_u256_vec(self.oprf_response_blinded),
        );
        map.insert(
            "oprf_response".to_owned(),
            affine_to_u256_vec(self.oprf_response),
        );
        map.insert("signal_hash".to_owned(), fq_to_u256_vec(self.signal_hash));
        map.insert(
            "current_timestamp".to_owned(),
            fq_to_u256_vec(self.current_timestamp),
        );

        map
    }
}
