//! Circuit input types for the World ID Protocol circuits.
//!
//! This module requires the `circuits` feature and is not available in WASM builds.

use std::collections::HashMap;

use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use groth16_material::circom::ProofInput;
use ruint::aliases::U256;

use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, MAX_AUTHENTICATOR_KEYS,
    authenticator_assertion::AatPublicValues, merkle::MerkleInclusionProof,
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
    /// The action for the proof request. See `ProofRequest` for more details.
    pub action: BaseField,
    /// The nonce of the proof request. See `ProofRequest` for more details.
    pub nonce: BaseField,
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
    /// [`claims_hash`, `associated_data_commitment`]
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
    /// Packed `Credential` `id` and `issuer_version` that occupies the last
    /// slot of the credential hash permutation. The value is the field element
    /// representation of `BigInt([id, issuer_version, 0, 0])`, i.e.
    /// `id + issuer_version`.
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
    /// The hashed signal provided by the RP and committed to by the user. See `ProofRequest` for more details.
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

/// Inputs for the "Proof of Ownership" (WIP-103) circuit.
#[derive(Debug, Clone)]
pub struct OwnershipProofCircuitInput<const MAX_DEPTH: usize> {
    /// Private input. The index of the authenticator key used to sign the proof request
    pub key_index: u64,
    /// Private input. The full authenticator key set for the user's World ID
    pub key_set: AuthenticatorPublicKeySet,
    /// Private input (**except** the `merkle_root`). The inclusion proof in the `WorldIDRegistry`
    pub inclusion_proof: MerkleInclusionProof<MAX_DEPTH>,
    /// **Public input**. The nonce of the proof request as provided by the verifier.
    pub nonce: FieldElement,
    /// **Public input**. The commitment being proven (e.g. a Credential's `sub`). The circuit
    /// asserts it equals `H(domainSeparator, leaf_index, commitment_blinder)`, so proving fails
    /// if it does not match the `inclusion_proof`'s leaf index and the `commitment_blinder`.
    pub expected_commitment: FieldElement,
    /// **Public input**. The verifier-supplied context for which the proof is valid. This usually encodes an
    /// explicit operation to perform. For example, "delete a credential". Please review WIP-103 for details on how
    /// the `context` should be used.
    pub context: FieldElement,
    /// Private input. Signature from the authenticator on the query.
    pub signature: EdDSASignature,
    /// Private input. The blinder used in the hash to compute the [`Self::expected_commitment`]. This is usually
    /// a randomly generated seed.
    pub commitment_blinder: FieldElement,
}

/// Public inputs of the "Proof of Embedding Similarity" (WIP-202) circuit that the verifier
/// supplies. The `merkle_root` is not one of them: the proof carries it.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingSimilarityPublicInputs {
    /// The proof time in Unix seconds: the Flamingo Token's `now`.
    pub now: u32,
    /// The RP the proof is for: the Flamingo Token's `aud`.
    pub rp_id: FieldElement,
    /// The RP request's nonce: the Flamingo Token's `nonce`.
    pub nonce: FieldElement,
    /// `R(SHA-256)` of the RP's challenge image. Must not be zero.
    pub challenge_hash: FieldElement,
    /// The RP's signal, hashed as for Uniqueness Proofs.
    pub signal_hash: FieldElement,
    /// The session commitment, or `0` for no session.
    pub session_id: FieldElement,
    /// The Flamingo Verifier key that signed the token.
    pub flamingo_verifier_key: EdDSAPublicKey,
    /// The Engine configuration hash the token was produced under.
    pub engine_config_hash: FieldElement,
    /// The AAT values, if the Flamingo Verifier verified an AAT; all zero in the circuit otherwise.
    pub aat: Option<AatPublicValues>,
    /// The PoH Credential's issuer schema.
    pub issuer_schema_id: u64,
    /// The PoH Credential's issuer version.
    pub issuer_version: u8,
    /// The PoH Credential's issuer key.
    pub cred_pk: EdDSAPublicKey,
    /// The RP's minimum Credential `genesis_issued_at`.
    pub genesis_issued_at_min: u64,
    /// The RP's minimum Credential `expires_at`, exclusive.
    pub expires_at_min: u64,
}

/// Inputs for the "Proof of Embedding Similarity" (WIP-202) circuit.
#[derive(Debug, Clone)]
pub struct EmbeddingSimilarityCircuitInput<const MAX_DEPTH: usize> {
    /// **Public inputs** supplied by the verifier.
    pub public: EmbeddingSimilarityPublicInputs,
    /// Private input. The Flamingo Token's `compared_entry_hash_1`: `R(SHA-256)` of the live capture.
    pub live_capture_hash: FieldElement,
    /// Private input. The Flamingo Token's WIP-107 billing nullifier, or `0` for an RP that is not billed.
    pub billing_nullifier: FieldElement,
    /// Private input. The Flamingo Verifier's signature over the token digest.
    pub token_signature: EdDSASignature,
    /// Private input. The index of the authenticator key that signed the authorization message.
    pub key_index: u64,
    /// Private input. The full authenticator key set for the user's World ID.
    pub key_set: AuthenticatorPublicKeySet,
    /// Private input (**except** the `merkle_root`). The inclusion proof in the `WorldIDRegistry`.
    pub inclusion_proof: MerkleInclusionProof<MAX_DEPTH>,
    /// Private input. The authenticator's signature over the WIP-202 authorization message.
    pub signature: EdDSASignature,
    /// Private input. The PoH Credential's claims; `claims[0]` commits to [`Self::hashes_json`].
    pub claims: [FieldElement; Credential::MAX_CLAIMS],
    /// Private input. The PoH Credential's associated data hash.
    pub associated_data_hash: FieldElement,
    /// Private input. The PoH Credential's `genesis_issued_at`.
    pub genesis_issued_at: u64,
    /// Private input. The PoH Credential's `expires_at`.
    pub expires_at: u64,
    /// Private input. The blinding factor of the PoH Credential's `sub`.
    pub sub_blinding_factor: FieldElement,
    /// Private input. The PoH Credential's issuer-scoped `id`.
    pub credential_id: u64,
    /// Private input. The issuer's signature over the PoH Credential.
    pub credential_signature: EdDSASignature,
    /// Private input. The raw PCP `hashes.json` bytes the Credential claim commits to.
    pub hashes_json: Vec<u8>,
    /// Private input. The blinding factor of the session commitment.
    pub session_id_r: FieldElement,
    /// Private input. The WIP-107 `billingAction` the billing nullifier is registered under.
    pub billing_action: FieldElement,
    /// Private input. The unblinded OPRF output `(x, y)` of the WIP-107 billing query.
    pub billing_oprf_output: [FieldElement; 2],
}
