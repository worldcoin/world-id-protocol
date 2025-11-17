#![deny(missing_docs)]
//! This crate provides a Rust client implementation for performing **Oblivious Pseudorandom Function (OPRF)** queries,
//! computing **Groth16 proofs**, and generating **nullifiers** for privacy-preserving protocols.
//! Currently, the main focus lies to be a building block for [WorldID v4.0](https://www.notion.so/worldcoin/World-ID-25-Protocol-v4-0-Product-Specs-High-Level-Technical-Specs-2588614bdf8c80e79f6bd132b8b23600#2588614bdf8c80e79f6bd132b8b23600).
//!
//! Most users will interact with the high-level [`nullifier`] function, which handles the full workflow asynchronously.
//!
//! ## Key Features
//!
//! - Sign and blind queries using user credentials.
//! - Initiate and manage asynchronous sessions with OPRF service peers.
//! - Compute DLog equality challenges using Shamir interpolation.
//! - Generate and verify Groth16 proofs for queries and nullifiers.
//!
//! ## Asynchronous Runtime
//!
//! - Uses `reqwest` under the hood for HTTP requests to OPRF services.
//! - Requires a `tokio` runtime to drive async sessions.
//!
//! Depending on future needs, we will add a blocking API as well.
//!
//! ## Notes and Best Practices
//!
//! - **Most users** only need [`nullifier`] for generating nullifiers in typical scenarios.
//! - Ensure enough OPRF services are provided and `threshold` is set correctly; insufficient responses will cause errors.
//! - Cryptographically secure randomness (`Rng + CryptoRng`) must be provided for all proof operations.
//! - Internally, the crate uses `arkworks` for Groth16 and `eddsa_babyjubjub` for elliptic curve operations.
//!
//! ## Module Overview
//!
//! - `client` – High-level client API including [`nullifier`].
//! - `nonblocking` – Async session management for contacting OPRF peers.
//! - `zk` – Zero-knowledge proof generation, verification, and Groth16 helpers.
//! - `types` – Supporting structs like `OprfQuery`, `CredentialsSignature`, `UserKeyMaterial`, and `MerkleMembership`.

use oprf_core::ddlog_equality::PartialDLogEqualityCommitments;

use oprf_core::oprf::{BlindedOPrfRequest, OprfClient};

use ark_ec::AffineRepr;
use oprf_core::ddlog_equality::DLogEqualityCommitments;
use oprf_types::api::v1::{
    ChallengeRequest, ChallengeResponse, NullifierShareIdentifier, OprfRequest, OprfResponse,
};
use oprf_types::crypto::{PartyId, RpNullifierKey};
use oprf_types::{RpId, ShareEpoch};
use oprf_world_types::api::v1::OprfRequestAuth;
use oprf_world_types::proof_inputs::nullifier::NullifierProofInput;
use oprf_world_types::proof_inputs::query::{QueryProofInput, MAX_PUBLIC_KEYS};
use oprf_world_types::TREE_DEPTH;
use oprf_zk::groth16_serde::Groth16Proof;
use oprf_zk::{Groth16Error, Groth16Material};
use poseidon2::{Poseidon2, POSEIDON2_BN254_T16_PARAMS};
use rand::{CryptoRng, Rng};
use reqwest::StatusCode;
use uuid::Uuid;
use world_id_primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_primitives::merkle::MerkleInclusionProof;
use world_id_primitives::proof::SingleProofInput;
use world_id_primitives::{Credential, FieldElement};

pub use groth16;

pub mod nonblocking;

/// Helper function to compute the claims hash for a credential
fn compute_claims_hash(credential: &Credential) -> Result<ark_babyjubjub::Fq> {
    let hasher = Poseidon2::new(&POSEIDON2_BN254_T16_PARAMS);
    if credential.claims.len() > Credential::MAX_CLAIMS {
        return Err(Error::InternalError(eyre::eyre!(
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

type Result<T> = std::result::Result<T, Error>;

/// General error type for the OPRF client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// API error returned by the OPRF service.
    #[error("API error {status}: {message}")]
    ApiError {
        /// the HTTP status code
        status: StatusCode,
        /// the error message
        message: String,
    },
    /// HTTP or network errors from OPRF service requests.
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    /// Not enough OPRF responses received to satisfy the required threshold.
    #[error("expected degree {threshold} responses, got {n}")]
    NotEnoughOprfResponses {
        /// actual amount responses
        n: usize,
        /// expected threshold
        threshold: usize,
    },
    /// The DLog equality proof failed verification.
    #[error("DLog proof could not be verified")]
    InvalidDLogProof,
    /// Provided public key index is out of valid range.
    #[error("Index in public-key batch must be in range [0..6], but is {0}")]
    InvalidPublicKeyIndex(u64),
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    /// Catch-all for other internal errors.
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}

/// The basic request a client sends to the OPRF service.
///
/// It contains the relying party’s ID, the share epoch, the action
/// the user wants to compute a nullifier for, and a fresh nonce.
/// The RP signs `(nonce || timestamp)` (both in little-endian byte encoding)
/// to prevent replay. That signature is included here.
#[derive(Clone)]
pub struct OprfQuery {
    /// The ID of the RP that issued the nonce.
    pub rp_id: RpId,
    /// The epoch of the DLog share (currently always `0`).
    pub share_epoch: ShareEpoch,
    /// The action the user wants to compute a nullifier for.
    pub action: ark_babyjubjub::Fq,
    /// The nonce obtained from the RP.
    pub nonce: ark_babyjubjub::Fq,
    /// The timestamp obtained from the RP.
    pub current_time_stamp: u64,
    /// The RP's signature over `(nonce || timestamp)`.
    pub nonce_signature: k256::ecdsa::Signature,
}

/// A signed OPRF query ready.
///
/// This struct holds all information needed to initiate OPRF sessions:
/// - `request_id`: Unique identifier for this query/request.
/// - `oprf_request`: The fully formed [`OprfRequest`] including the
///   blinded query point and Groth16 proof.
/// - `query`: Original query details (RP ID, action, nonce, timestamp).
/// - `blinded_request`: The result of blinding the query with the user's key.
/// - `query_input`: Input data for the OPRFQuery proof.
/// - `query_hash`: The generated query hash.
pub struct SignedOprfQuery {
    request_id: Uuid,
    oprf_request: OprfRequest<OprfRequestAuth>,
    query: OprfQuery,
    blinded_request: BlindedOPrfRequest,
    query_input: QueryProofInput<TREE_DEPTH>,
    query_hash: ark_babyjubjub::Fq,
}

/// Holds information about active OPRF sessions with multiple peers.
///
/// Tracks the peer services, their party IDs, and the partial DLog equality
/// commitments received from each peer.
pub struct OprfSessions {
    services: Vec<String>,
    party_ids: Vec<PartyId>,
    commitments: Vec<PartialDLogEqualityCommitments>,
}

impl OprfSessions {
    /// Creates an empty [`OprfSessions`] with preallocated capacity.
    ///
    fn with_capacity(capacity: usize) -> Self {
        Self {
            services: Vec::with_capacity(capacity),
            party_ids: Vec::with_capacity(capacity),
            commitments: Vec::with_capacity(capacity),
        }
    }

    /// Adds a peer's response to the sessions.
    fn push(&mut self, service: String, response: OprfResponse) {
        self.services.push(service);
        self.party_ids.push(response.party_id);
        self.commitments.push(response.commitments);
    }

    /// Returns the number of sessions currently stored.
    fn len(&self) -> usize {
        self.services.len()
    }
}

/// An OPRF challenge for a given query.
///
/// This struct holds all information needed to compute and verify the
/// DLogEquality challenge for a query:
/// - `request_id`: Unique identifier for this query/request.
/// - `challenge_request`: The challenge request that will be sent to OPRF peers.
/// - `blinded_request`: The original blinded OPRF request from the user.
///   generating the OPRFNullifier proof.
/// - `blinded_response`: The combined blinded response after aggregating
///   peer commitments.
/// - `query_input`: Input data used to generate the OPRFQuery proof.
/// - `query_hash`: The hash of the query used in proofs.
/// - `rp_nullifier_key`: The RP-specific nullifier public-key.
pub struct Challenge {
    request_id: Uuid,
    challenge_request: ChallengeRequest,
    blinded_request: BlindedOPrfRequest,
    blinded_response: ark_babyjubjub::EdwardsAffine,
    query_input: QueryProofInput<TREE_DEPTH>,
    query_hash: ark_babyjubjub::Fq,
    rp_nullifier_key: RpNullifierKey,
}

impl Challenge {
    /// Returns the [`ChallengeRequest`] for this challenge.
    pub fn get_request(&self) -> ChallengeRequest {
        self.challenge_request.clone()
    }
}

impl SignedOprfQuery {
    /// Returns the [`OprfRequest`] for this signed query.
    pub fn get_request(&self) -> OprfRequest<OprfRequestAuth> {
        self.oprf_request.clone()
    }

    /// Returns the [`QueryProofInput`] that was committed to in the query proof.
    pub fn query_input(&self) -> &QueryProofInput<TREE_DEPTH> {
        &self.query_input
    }

    /// Returns the query hash bound into the query proof.
    pub fn query_hash(&self) -> ark_babyjubjub::Fq {
        self.query_hash
    }
}

/// Generates a nullifier proof for a given query.
///
/// This is the main entry point for most users. It handles the full workflow:
/// 1. Signs and blinds the OPRF query using the user's credentials and key material.
/// 2. Initiates sessions with the provided OPRF services and waits for enough responses.
///    This uses asynchronous HTTP requests via [`reqwest`] and requires a [`tokio`] runtime.
/// 3. Computes the DLog equality challenges using Shamir interpolation.
/// 4. Collects the responses and verifies the challenges.
/// 5. Generates the final Groth16 nullifier proof along with public inputs.
///
/// **Note**: the timestamps in the credentials must be given as UNIX seconds
///
/// # Arguments
///
/// * `services` - List of OPRF service URLs to contact.
/// * `threshold` - Minimum number of valid peer responses required.
/// * `args` - [`SingleProofInput`] containing all input data (credentials, Merkle membership, query, keys, signal, etc.).
/// * `private_key` - The user's private key for signing the blinded query.
/// * `query_material` - Groth16 material (proving key and matrices) used for the query proof.
/// * `nullifier_material` - Groth16 material (proving key and matrices) used for the nullifier proof.
/// * `rng` - A cryptographically secure random number generator.
///
/// # Returns
///
/// On success, returns a tuple:
/// 1. [`Groth16Proof`] – the generated nullifier proof,
/// 2. `Vec<ark_babyjubjub::Fq>` – the public inputs for the proof,
/// 3. `ark_babyjubjub::Fq` – the computed nullifier.
/// 4. `ark_babyjubjub::Fq` – the computed identity commitment.
///
/// # Errors
///
/// Returns [`Error`] in the following cases:
/// * `InvalidPublicKeyIndex` – the user key index is out of range.
/// * `InvalidDLogProof` – the DLog equality proof could not be verified.
/// * Other errors may propagate from network requests, proof generation, or Groth16 verification.
pub async fn nullifier<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    query_material: &Groth16Material,
    nullifier_material: &Groth16Material,
    args: SingleProofInput<TREE_DEPTH>,
    private_key: &eddsa_babyjubjub::EdDSAPrivateKey,
    rng: &mut R,
) -> Result<(
    Groth16Proof,
    Vec<ark_babyjubjub::Fq>,
    ark_babyjubjub::Fq,
    ark_babyjubjub::Fq,
)> {
    let SingleProofInput {
        credential,
        inclusion_proof,
        key_set,
        key_index,
        rp_session_id_r_seed,
        rp_id,
        share_epoch,
        action,
        nonce,
        current_timestamp,
        rp_signature,
        rp_nullifier_key,
        signal_hash,
    } = args;

    let request_id = Uuid::new_v4();

    // Convert to oprf_types
    let oprf_rp_id = RpId::new(rp_id.into_inner());
    let oprf_rp_nullifier_key =
        oprf_types::crypto::RpNullifierKey::new(rp_nullifier_key.into_inner());

    // Construct OprfQuery from SingleProofInput fields
    let query = OprfQuery {
        rp_id: oprf_rp_id,
        share_epoch: ShareEpoch::new(share_epoch),
        action: *action,
        nonce: *nonce,
        current_time_stamp: current_timestamp,
        nonce_signature: rp_signature,
    };

    let signed_query = sign_oprf_query(
        credential,
        inclusion_proof,
        query_material,
        query,
        key_set,
        key_index,
        private_key,
        request_id,
        rng,
    )?;

    let client = reqwest::Client::new();
    let req = signed_query.get_request();
    let sessions = nonblocking::init_sessions(&client, services, threshold, req).await?;

    let challenges = compute_challenges(signed_query, &sessions, oprf_rp_nullifier_key)?;
    let req = challenges.get_request();
    let responses = nonblocking::finish_sessions(&client, sessions, req).await?;
    verify_challenges(
        nullifier_material,
        challenges,
        responses,
        *signal_hash,
        *rp_session_id_r_seed,
        rng,
    )
}

/// Signs an OPRF query and prepares it for sending to OPRF peers.
///
/// This function performs the following steps:
/// 1. Validates inputs, including Merkle tree depth and public key index.
/// 2. Generates a query hash from the Merkle index, RP identifier, and requested action.
/// 3. Blinds the query hash using the user's public key and a random blinding factor.
/// 4. Signs the blinded query with the user’s private key.
/// 5. Constructs a [`QueryProofInput`] containing the signature, credential data,
///    Merkle membership information, and other metadata required for the proof.
/// 6. Generates the OPRFQuery zero-knowledge proof using the provided
///    proving key material.
///
/// # Arguments
///
/// * `credential` - The user's credential.
/// * `inclusion_proof` - Merkle inclusion proof for membership in the tree.
/// * `query_material` - Groth16 proving key and constraint matrices for query proof.
/// * `query` - The query details (RP ID, action, nonce, timestamp).
/// * `key_set` - Set of authenticator public keys.
/// * `key_index` - Index of the key in the set to use for signing.
/// * `private_key` - The user's private key for signing.
/// * `request_id` - Unique identifier for this request.
/// * `rng` - Cryptographically secure random number generator.
///
/// # Errors
///
/// Returns an [`Error`] if:
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
    credential: Credential,
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    query_material: &Groth16Material,
    query: OprfQuery,
    key_set: AuthenticatorPublicKeySet,
    key_index: u64,
    private_key: &eddsa_babyjubjub::EdDSAPrivateKey,
    request_id: Uuid,
    rng: &mut R,
) -> Result<SignedOprfQuery> {
    if key_index >= MAX_PUBLIC_KEYS as u64 {
        return Err(Error::InvalidPublicKeyIndex(key_index));
    }

    let query_hash = OprfClient::generate_query(
        inclusion_proof.leaf_index.into(),
        query.rp_id.into_inner().into(),
        query.action,
    );
    let public_key = key_set[key_index as usize].pk;
    let oprf_client = OprfClient::new(public_key);
    let (blinded_request, blinding_factor) = oprf_client.blind_query(request_id, query_hash, rng);
    let signature = private_key.sign(blinding_factor.query());

    // Convert AuthenticatorPublicKeySet to array of EdwardsAffine
    let mut pk_array = [ark_babyjubjub::EdwardsAffine::default(); MAX_PUBLIC_KEYS];
    for (i, pubkey) in key_set.iter().enumerate() {
        pk_array[i] = pubkey.pk;
    }

    // Compute claims hash from credential
    let claims_hash = compute_claims_hash(&credential)?;

    // Get signature from credential
    let cred_signature = credential
        .signature
        .ok_or_else(|| Error::InternalError(eyre::eyre!("Credential not signed")))?;

    let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] = inclusion_proof.siblings.map(|s| *s);

    let query_input = QueryProofInput::<TREE_DEPTH> {
        pk: pk_array,
        pk_index: key_index.into(),
        s: signature.s,
        r: signature.r,
        cred_type_id: credential.issuer_schema_id.into(),
        cred_pk: credential.issuer.pk,
        cred_hashes: [claims_hash, *credential.associated_data_hash],
        cred_genesis_issued_at: credential.genesis_issued_at.into(),
        cred_expires_at: credential.expires_at.into(),
        cred_s: cred_signature.s,
        cred_r: cred_signature.r,
        current_time_stamp: query.current_time_stamp.into(),
        merkle_root: *inclusion_proof.root,
        depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
        mt_index: inclusion_proof.leaf_index.into(),
        siblings,
        beta: blinding_factor.beta(),
        rp_id: query.rp_id.into_inner().into(),
        action: query.action,
        nonce: query.nonce,
    };

    let query_input_json = serde_json::to_value(&query_input)
        .expect("can serialize")
        .as_object()
        .expect("is object")
        .to_owned();
    let witness = query_material.generate_witness(query_input_json)?;
    let (proof, _) = query_material.generate_proof(&witness, rng)?;

    Ok(SignedOprfQuery {
        request_id,
        query_hash,
        query_input,
        oprf_request: OprfRequest {
            request_id,
            blinded_query: blinded_request.blinded_query(),
            rp_identifier: NullifierShareIdentifier {
                rp_id: query.rp_id,
                share_epoch: query.share_epoch,
            },
            auth: OprfRequestAuth {
                proof,
                action: query.action,
                nonce: query.nonce,
                merkle_root: oprf_world_types::MerkleRoot::from(*inclusion_proof.root),
                cred_pk: credential.issuer,
                current_time_stamp: query.current_time_stamp,
                signature: query.nonce_signature,
            },
        },
        blinded_request,
        query,
    })
}

/// Computes the DLog equality challenges for a signed OPRF query.
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
/// * `query` - The signed OPRF query produced by [`sign_oprf_query`].
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
    let challenge = DLogEqualityCommitments::combine_commitments_shamir(
        &sessions.commitments,
        contributing_parties,
    );
    let blinded_response = challenge.blinded_response();
    Ok(Challenge {
        query_input: query.query_input,
        query_hash: query.query_hash,
        request_id: query.request_id,
        blinded_request: query.blinded_request,
        blinded_response,
        rp_nullifier_key,
        challenge_request: ChallengeRequest {
            request_id: query.request_id,
            challenge,
            rp_identifier: NullifierShareIdentifier {
                rp_id: query.query.rp_id,
                share_epoch: query.query.share_epoch,
            },
        },
    })
}

/// Verifies the combined DLogEquality challenge and generates the
/// corresponding OPRFNullifier proof.
///
/// This function performs the following steps:
/// 1. Combines the partial proofs from peers using Lagrange coefficients.
/// 2. Verifies the resulting DLogEquality proof against the blinded query
///    and aggregated response.
/// 3. Constructs a [`NullifierProofInput`] for the OPRFNullifier circuit.
/// 4. Generates an OPRFNullifier Groth16 proof for the provided proving key.
///
/// # Arguments
///
/// * `nullifier_material` - Groth16 material (proving key and matrices) used for nullifier proof.
/// * `challenges` - The [`Challenge`] struct containing all challenge data.
/// * `responses` - Responses from peers during the finish session. Must be in the same order
///   as the initial sessions to match the Lagrange coefficients.
/// * `signal_hash` - The signal hash as in semaphore.
/// * `id_commitment_r` - Commitment to the id.
/// * `rng` - Cryptographically secure RNG.
///
/// # Returns
///
/// On success, returns a tuple `(proof, public_inputs, nullifier)`:
/// - `proof`: The Groth16 nullifier proof.
/// - `public_inputs`: Public inputs used in the proof verification.
/// - `nullifier`: The computed nullifier.
/// - `id_commitment`: The computed identity_commitment.
///
/// # Errors
///
/// Returns [`Error::InvalidDLogProof`] if the combined DLogEquality proof
/// fails verification, or any [`Groth16Error`] if proof generation fails.
pub fn verify_challenges<R: Rng + CryptoRng>(
    nullifier_material: &Groth16Material,
    challenges: Challenge,
    responses: Vec<ChallengeResponse>,
    signal_hash: ark_babyjubjub::Fq,
    id_commitment_r: ark_babyjubjub::Fq,
    rng: &mut R,
) -> Result<(
    Groth16Proof,
    Vec<ark_babyjubjub::Fq>,
    ark_babyjubjub::Fq,
    ark_babyjubjub::Fq,
)> {
    let proofs = responses
        .into_iter()
        .map(|res| res.proof_share)
        .collect::<Vec<_>>();
    let party_ids = challenges
        .challenge_request
        .challenge
        .get_contributing_parties()
        .to_vec();
    let dlog_proof = challenges.challenge_request.challenge.combine_proofs(
        challenges.request_id,
        &party_ids,
        &proofs,
        challenges.rp_nullifier_key.inner(),
        challenges.blinded_request.blinded_query(),
    );
    if !dlog_proof.verify(
        challenges.rp_nullifier_key.inner(),
        challenges.blinded_request.blinded_query(),
        challenges.blinded_response,
        ark_babyjubjub::EdwardsAffine::generator(),
    ) {
        return Err(Error::InvalidDLogProof);
    }

    let nullifier_input = NullifierProofInput::new(
        challenges.request_id,
        challenges.query_input,
        dlog_proof,
        challenges.rp_nullifier_key.inner(),
        challenges.blinded_response,
        signal_hash,
        id_commitment_r,
        challenges.query_hash,
    );

    let nullifier_input_json = serde_json::to_value(&nullifier_input)
        .expect("can serialize")
        .as_object()
        .expect("is object")
        .to_owned();
    let witness = nullifier_material.generate_witness(nullifier_input_json)?;
    let (proof, public) = nullifier_material.generate_proof(&witness, rng)?;

    // 2 outputs, 0 is id_commitment, 1 is nullifier
    let id_commitment = public[0];
    let nullifier = public[1];

    Ok((proof, public, nullifier, id_commitment))
}
