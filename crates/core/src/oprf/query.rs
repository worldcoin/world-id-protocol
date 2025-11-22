//! OPRF query signing and preparation.
//!
//! This module handles the creation of signed OPRF queries, which include:
//! - Blinding the query hash using the user's public key
//! - Signing the blinded query with the user's private key
//! - Generating a Groth16 proof (Query Proof, π1)
//!
//! The signed query is then sent to OPRF service peers to initiate sessions.

use oprf_core::oprf::{self, BlindedOprfRequest, BlindingFactor};
use oprf_types::api::v1::NullifierShareIdentifier;
use oprf_types::api::v1::OprfRequest;
use oprf_types::{RpId as OprfRpId, ShareEpoch};
use poseidon2::{Poseidon2, POSEIDON2_BN254_T16_PARAMS};
use rand::{CryptoRng, Rng};
use uuid::Uuid;
use world_id_primitives::circuit_inputs::QueryProofCircuitInput;
use world_id_primitives::oprf::OprfRequestAuthV1;
use world_id_primitives::proof::SingleProofInput;
use world_id_primitives::{Credential, FieldElement, TREE_DEPTH};

use crate::proof::CircomGroth16Material;

use super::ProofError;

type Result<T> = std::result::Result<T, ProofError>;

/// A signed OPRF query ready to be sent to OPRF service peers.
///
/// This struct holds all information needed to initiate OPRF sessions:
/// - `request_id`: Unique identifier for this query/request.
/// - `oprf_request`: The fully formed [`OprfRequest`] including the
///   blinded query point and Groth16 proof.
/// - `blinded_request`: The result of blinding the query with the user's key.
/// - `query_input`: Input data for the `OPRFQuery` proof.
/// - `blinding_factor`: The hash of the query used in proofs.
pub struct SignedOprfQuery {
    pub(super) request_id: Uuid,
    pub(super) oprf_request: OprfRequest<OprfRequestAuthV1>,
    pub(super) blinded_request: BlindedOprfRequest,
    pub(super) query_input: QueryProofCircuitInput<TREE_DEPTH>,
    pub(super) blinding_factor: BlindingFactor,
}

impl SignedOprfQuery {
    /// Returns the [`OprfRequest`] for this signed query.
    #[must_use]
    pub fn get_request(&self) -> OprfRequest<OprfRequestAuthV1> {
        self.oprf_request.clone()
    }

    /// Returns the [`QueryProofCircuitInput`] that was committed to in the query proof.
    #[must_use]
    pub const fn query_input(&self) -> &QueryProofCircuitInput<TREE_DEPTH> {
        &self.query_input
    }

    /// Returns the [`BlindingFactor`] for this signed query
    #[must_use]
    pub const fn blinding_factor(&self) -> &BlindingFactor {
        &self.blinding_factor
    }
}

/// Signs an OPRF query and prepares it for sending to OPRF peers.
///
/// This function performs the following steps:
/// 1. Validates inputs, including Merkle tree depth and public key index.
/// 2. Generates a query hash from the Merkle index, RP identifier, and requested action.
/// 3. Blinds the query hash using the user's public key and a random blinding factor.
/// 4. Signs the blinded query with the user's private key.
/// 5. Constructs a [`QueryProofInput`] containing the signature, credential data,
///    Merkle membership information, and other metadata required for the proof.
/// 6. Generates the `OPRFQuery` zero-knowledge proof using the provided
///    proving key material.
///
/// # Arguments
///
/// * `args` - [`SingleProofInput`] containing all input data (credentials, Merkle membership, query, keys, signal, etc.).
/// * `query_material` - Groth16 proving key and constraint matrices for query proof.
/// * `private_key` - The user's private key for signing.
/// * `request_id` - Unique identifier for this request.
/// * `rng` - Cryptographically secure random number generator.
///
/// # Errors
///
/// Returns a [`ProofError`] if:
/// - The public key index is out of bounds.
/// - Groth16 proof generation fails.
///
/// # Returns
///
/// A [`SignedOprfQuery`] containing:
/// - The generated `OprfRequest` ready to initiate sessions with OPRF peers.
/// - The blinding factor and query hash used for later computations.
/// - The Groth16 proof input for verification in the nullifier step.
pub fn sign_oprf_query<R: Rng + CryptoRng>(
    args: &SingleProofInput<TREE_DEPTH>,
    query_material: &CircomGroth16Material,
    private_key: &eddsa_babyjubjub::EdDSAPrivateKey,
    request_id: Uuid,
    rng: &mut R,
) -> Result<SignedOprfQuery> {
    let rp_id = OprfRpId::new(args.rp_id.into_inner()); // Convert to `oprf_types`

    let cred_signature = args
        .credential
        .signature
        .clone()
        .ok_or_else(|| ProofError::InternalError(eyre::eyre!("Credential not signed")))?;

    let query_hash = oprf::client::generate_query(
        args.inclusion_proof.account_id.into(),
        args.rp_id.into_inner().into(),
        *args.action,
    );

    let (blinded_request, blinding_factor) = oprf::client::blind_query(query_hash, rng);
    let signature = private_key.sign(blinding_factor.query());

    // Compute claims hash from credential
    let claims_hash = compute_claims_hash(&args.credential)?;

    let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] = args.inclusion_proof.siblings.map(|s| *s);

    let query_input = QueryProofCircuitInput::<TREE_DEPTH> {
        pk: args.key_set.as_affine_array(),
        pk_index: args.key_index.into(),
        s: signature.s,
        r: signature.r,
        cred_type_id: args.credential.issuer_schema_id.into(),
        cred_pk: args.credential.issuer.pk,
        cred_hashes: [claims_hash, *args.credential.associated_data_hash],
        cred_genesis_issued_at: args.credential.genesis_issued_at.into(),
        cred_expires_at: args.credential.expires_at.into(),
        cred_s: cred_signature.s,
        cred_r: cred_signature.r,
        current_timestamp: args.current_timestamp.into(),
        merkle_root: *args.inclusion_proof.root,
        depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
        mt_index: args.inclusion_proof.account_id.into(),
        siblings,
        beta: blinding_factor.beta(),
        rp_id: rp_id.into_inner().into(),
        action: *args.action,
        nonce: *args.nonce,
    };

    tracing::debug!("generate query proof");
    let (proof, _) = query_material.generate_proof(&query_input, rng)?;

    Ok(SignedOprfQuery {
        request_id,
        blinding_factor,
        query_input,
        oprf_request: OprfRequest {
            request_id,
            blinded_query: blinded_request.blinded_query(),
            rp_identifier: NullifierShareIdentifier {
                rp_id,
                share_epoch: ShareEpoch::new(args.share_epoch),
            },
            auth: OprfRequestAuthV1 {
                proof: proof.into(),
                action: *args.action,
                nonce: *args.nonce,
                merkle_root: *args.inclusion_proof.root,
                cred_pk: args.credential.issuer.clone(),
                current_time_stamp: args.current_timestamp,
                signature: args.rp_signature,
            },
        },
        blinded_request,
    })
}

/// Helper function to compute the claims hash for a credential.
/// TODO: Move to primitives.
fn compute_claims_hash(credential: &Credential) -> Result<ark_babyjubjub::Fq> {
    let hasher = Poseidon2::new(&POSEIDON2_BN254_T16_PARAMS);
    if credential.claims.len() > Credential::MAX_CLAIMS {
        return Err(ProofError::InternalError(eyre::eyre!(
            "There can be at most {} claims",
            Credential::MAX_CLAIMS
        )));
    }
    let mut input = [*FieldElement::ZERO; Credential::MAX_CLAIMS];
    for (i, claim) in credential.claims.iter().enumerate() {
        input[i] = **claim;
    }
    hasher.permutation_in_place(&mut input);
    Ok(input[1])
}
