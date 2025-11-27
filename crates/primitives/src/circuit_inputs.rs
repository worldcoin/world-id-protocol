use std::collections::HashMap;

use groth16_material::circom::ProofInput;
use ruint::aliases::U256;

use crate::authenticator::MAX_AUTHENTICATOR_KEYS;

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

/// The input for the circuit of the OPRF Query Proof.
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
    /// The id as registered in the `CredentialSchemaIssuerRegistry` representing the (issuer, schema) pair.
    ///
    /// This is the `issuer_schema_id` field of the `Credential` type.
    pub cred_type_id: BaseField,
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
    /// The current timestamp.
    pub current_timestamp: BaseField,
    /// The root of the Merkle tree of the `AccountRegistry` contract.
    pub merkle_root: BaseField,
    /// The depth of the Merkle tree of the `AccountRegistry` contract.
    pub depth: BaseField,
    /// The leaf index of the World ID in the Merkle tree of the `AccountRegistry` contract.
    ///
    /// In the `MerkleInclusionProof` type, this is the `leaf_index` field.
    pub mt_index: BaseField,
    /// The siblings of the Merkle proof of the account in the `AccountRegistry` contract.
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

impl<const MAX_DEPTH: usize> ProofInput for QueryProofCircuitInput<MAX_DEPTH> {
    fn prepare_input(&self) -> HashMap<String, Vec<U256>> {
        let mut map = HashMap::new();
        map.insert("pk".to_owned(), affine_seq_to_u256_vec(&self.pk));
        map.insert("pk_index".to_owned(), fq_to_u256_vec(self.pk_index));
        map.insert("s".to_owned(), fr_to_u256_vec(self.s));
        map.insert("r".to_owned(), affine_to_u256_vec(self.r));
        map.insert("cred_type_id".to_owned(), fq_to_u256_vec(self.cred_type_id));
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
            "cred_expires_at".to_owned(),
            fq_to_u256_vec(self.cred_expires_at),
        );
        map.insert("cred_s".to_owned(), fr_to_u256_vec(self.cred_s));
        map.insert("cred_r".to_owned(), affine_to_u256_vec(self.cred_r));
        map.insert(
            "current_time_stamp".to_owned(),
            fq_to_u256_vec(self.current_timestamp),
        );
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

/// The input for the circuit of the Nullifier Proof (`π2`).
///
/// Externally, the Nullifier Proof is exposed to RPs as a Uniqueness Proof or a Session Proof respectively.
#[derive(Debug, Clone)]
pub struct NullifierProofCircuitInput<const MAX_DEPTH: usize> {
    /// The input for the circuit of the OPRF Query Proof from which this nullifier proof is constructed.
    pub query_input: QueryProofCircuitInput<MAX_DEPTH>,
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
    /// The hashed signal provided by the RP and committed to by the user. See `SingleProofInput` for more details.
    pub signal_hash: BaseField,
    /// The random commitment for future session proofs generated by the Authenticator.
    ///
    /// TODO: Rename to match new terms and avoid confusion with World ID <3.0's `identity_commitment`.
    pub id_commitment_r: BaseField,
}

impl<const MAX_DEPTH: usize> ProofInput for NullifierProofCircuitInput<MAX_DEPTH> {
    fn prepare_input(&self) -> std::collections::HashMap<String, Vec<ruint::aliases::U256>> {
        let mut map = self.query_input.prepare_input();
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
            "id_commitment_r".to_owned(),
            fq_to_u256_vec(self.id_commitment_r),
        );
        map
    }
}
