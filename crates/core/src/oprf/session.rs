//! OPRF session management and challenge computation.
//!
//! This module handles:
//! - Managing active OPRF sessions with multiple peers
//! - Computing `DLog` equality challenges using Shamir interpolation
//! - Verifying `DLog` proofs and generating nullifier proofs
//!
//! The session lifecycle consists of:
//! 1. Initiating sessions with OPRF peers (via HTTP backend)
//! 2. Computing challenges from peer responses
//! 3. Finishing sessions and verifying the combined `DLog` proof
//! 4. Generating the final nullifier proof

use ark_ec::AffineRepr;
use circom_types::ark_bn254::Bn254;
use circom_types::groth16::Proof;
use oprf_core::ddlog_equality::shamir::{DLogCommitmentsShamir, PartialDLogCommitmentsShamir};
use oprf_core::oprf::BlindedOprfRequest;
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, NullifierShareIdentifier};
use oprf_types::crypto::{PartyId, RpNullifierKey};
use rand::{CryptoRng, Rng};
use uuid::Uuid;
use world_id_primitives::circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput};
use world_id_primitives::TREE_DEPTH;

use crate::proof::CircomGroth16Material;

use super::query::SignedOprfQuery;
use super::ProofError;

type Result<T> = std::result::Result<T, ProofError>;

/// Holds information about active OPRF sessions with multiple peers.
///
/// Tracks the peer services, their party IDs, and the partial `DLog` equality
/// commitments received from each peer.
pub struct OprfSessions {
    pub(super) services: Vec<String>,
    party_ids: Vec<PartyId>,
    commitments: Vec<PartialDLogCommitmentsShamir>,
}

impl OprfSessions {
    /// Creates an empty [`OprfSessions`] with preallocated capacity.
    ///
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            services: Vec::with_capacity(capacity),
            party_ids: Vec::with_capacity(capacity),
            commitments: Vec::with_capacity(capacity),
        }
    }

    /// Adds a peer's response to the sessions.
    pub(super) fn push(&mut self, service: String, response: oprf_types::api::v1::OprfResponse) {
        self.services.push(service);
        self.party_ids.push(response.party_id);
        self.commitments.push(response.commitments);
    }

    /// Returns the number of sessions currently stored.
    pub(super) const fn len(&self) -> usize {
        self.services.len()
    }
}

/// An OPRF challenge for a given query.
///
/// This struct holds all information needed to compute and verify the
/// `DLogEquality` challenge for a query:
/// - `request_id`: Unique identifier for this query/request.
/// - `challenge_request`: The challenge request that will be sent to OPRF peers.
/// - `blinded_request`: The original blinded OPRF request from the user.
///   generating the `OPRFNullifier` proof.
/// - `blinded_response`: The combined blinded response after aggregating
///   peer commitments.
/// - `query_input`: Input data used to generate the `OPRFQuery` proof.
/// - `blinding_factor`: The hash of the query used in proofs.
/// - `rp_nullifier_key`: The RP-specific nullifier public-key.
pub struct Challenge {
    pub(super) request_id: Uuid,
    pub(super) request: ChallengeRequest,
    pub(super) blinded_request: BlindedOprfRequest,
    pub(super) blinded_response: ark_babyjubjub::EdwardsAffine,
    pub(super) query_input: QueryProofCircuitInput<TREE_DEPTH>,
    pub(super) blinding_factor: oprf_core::oprf::BlindingFactor,
    pub(super) rp_nullifier_key: RpNullifierKey,
}

impl Challenge {
    /// Returns the [`ChallengeRequest`] for this challenge.
    #[must_use]
    pub fn get_request(&self) -> ChallengeRequest {
        self.request.clone()
    }
}

/// Computes the `DLog` equality challenges for a signed OPRF query.
///
/// Given a [`SignedOprfQuery`] and the corresponding [`OprfSessions`] obtained
/// from the peers, this function computes the Lagrange coefficients over the
/// party IDs and combines the partial commitments to generate a single blinded
/// response and the challenge.
///
/// The output is a [`Challenge`] struct, which contains all information
/// needed to later verify the responses from the OPRF peers, including the
/// original query, proof inputs, Lagrange coefficients, and the generated
/// [`ChallengeRequest`].
///
/// # Arguments
///
/// * `query` - The signed OPRF query produced by [`sign_oprf_query`](super::sign_oprf_query).
/// * `sessions` - Active OPRF sessions containing the party IDs and commitments.
/// * `rp_nullifier_key` - The RP-specific nullifier key used for challenge computation.
///
/// # Errors
///
/// Returns an error if any internal step fails (e.g., invalid session state).
pub fn compute_challenges(
    query: SignedOprfQuery,
    sessions: &OprfSessions,
    rp_nullifier_key: RpNullifierKey,
) -> Result<Challenge> {
    let contributing_parties = sessions
        .party_ids
        .iter()
        .map(|id| id.into_inner() + 1)
        .collect::<Vec<_>>();
    // Combine commitments from all sessions and create a single challenge
    let challenge =
        DLogCommitmentsShamir::combine_commitments(&sessions.commitments, contributing_parties);
    let blinded_response = challenge.blinded_response();
    Ok(Challenge {
        query_input: query.query_input,
        blinding_factor: query.blinding_factor,
        request_id: query.request_id,
        blinded_request: query.blinded_request,
        blinded_response,
        rp_nullifier_key,
        request: ChallengeRequest {
            request_id: query.request_id,
            challenge,
            rp_identifier: NullifierShareIdentifier {
                rp_id: query.oprf_request.rp_identifier.rp_id,
                share_epoch: query.oprf_request.rp_identifier.share_epoch,
            },
        },
    })
}

/// Verifies the combined `DLogEquality` challenge and generates the
/// corresponding `OPRFNullifier` proof.
///
/// This function performs the following steps:
/// 1. Combines the partial proofs from peers using Lagrange coefficients.
/// 2. Verifies the resulting `DLogEquality` proof against the blinded query
///    and aggregated response.
/// 3. Constructs a [`NullifierProofInput`] for the `OPRFNullifier` circuit.
/// 4. Generates an `OPRFNullifier` Groth16 proof for the provided proving key.
///
/// # Arguments
///
/// * `nullifier_material` - Groth16 material (proving key and matrices) used for nullifier proof.
/// * `challenges` - The [`Challenge`] struct containing all challenge data.
/// * `responses` - Responses from peers during the finish session. Must be in the same order
///   as the initial sessions to match the Lagrange coefficients.
/// * `signal_hash` - The signal hash as in Semaphore.
/// * `id_commitment_r` - Commitment to the ID.
/// * `rng` - Cryptographically secure RNG.
///
/// # Returns
///
/// On success, returns a tuple `(proof, public_inputs, nullifier)`:
/// - `proof`: The Groth16 nullifier proof.
/// - `public_inputs`: Public inputs used in the proof verification.
/// - `nullifier`: The computed nullifier.
/// - `id_commitment`: The computed `identity_commitment`.
///
/// # Errors
///
/// Returns [`ProofError::InvalidDLogProof`] if the combined `DLogEquality` proof
/// fails verification, or any [`Groth16Error`] if proof generation fails.
pub fn verify_challenges<R: Rng + CryptoRng>(
    nullifier_material: &CircomGroth16Material,
    challenges: Challenge,
    responses: Vec<ChallengeResponse>,
    signal_hash: ark_babyjubjub::Fq,
    id_commitment_r: ark_babyjubjub::Fq,
    rng: &mut R,
) -> Result<(
    Proof<Bn254>,
    Vec<ark_babyjubjub::Fq>,
    ark_babyjubjub::Fq,
    ark_babyjubjub::Fq,
)> {
    let proofs = responses
        .into_iter()
        .map(|res| res.proof_share)
        .collect::<Vec<_>>();
    let party_ids = challenges
        .request
        .challenge
        .get_contributing_parties()
        .to_vec();
    let dlog_proof = challenges.request.challenge.combine_proofs(
        challenges.request_id,
        &party_ids,
        &proofs,
        challenges.rp_nullifier_key.inner(),
        challenges.blinded_request.blinded_query(),
    );
    dlog_proof
        .verify(
            challenges.rp_nullifier_key.inner(),
            challenges.blinded_request.blinded_query(),
            challenges.blinded_response,
            ark_babyjubjub::EdwardsAffine::generator(),
        )
        .map_err(|_| ProofError::InvalidDLogProof)?;

    let nullifier_input = NullifierProofCircuitInput::new(
        challenges.query_input,
        &dlog_proof,
        challenges.rp_nullifier_key.inner(),
        challenges.blinded_response,
        signal_hash,
        id_commitment_r,
        challenges.blinding_factor,
    );

    tracing::debug!("generate nullifier proof");
    let (proof, public) = nullifier_material.generate_proof(&nullifier_input, rng)?;

    // 2 outputs, 0 is id_commitment, 1 is nullifier
    let id_commitment = public[0];
    let nullifier = public[1];

    Ok((proof.into(), public, nullifier, id_commitment))
}
