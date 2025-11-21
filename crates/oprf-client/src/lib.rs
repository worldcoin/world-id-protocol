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

use std::io::Read;
use std::path::Path;

use circom_types::ark_bn254::Bn254;
use circom_types::groth16::Proof;
use groth16_material::Groth16Error;
use oprf_core::ddlog_equality::shamir::{DLogCommitmentsShamir, PartialDLogCommitmentsShamir};

use oprf_core::oprf::{self, BlindedOprfRequest, BlindingFactor};

use ark_ec::AffineRepr;
use oprf_types::api::v1::{
    ChallengeRequest, ChallengeResponse, NullifierShareIdentifier, OprfRequest, OprfResponse,
};
use oprf_types::crypto::{PartyId, RpNullifierKey};
use oprf_types::{crypto::RpNullifierKey as OprfRpNullifierKey, RpId as OprfRpId, ShareEpoch};
use poseidon2::{Poseidon2, POSEIDON2_BN254_T16_PARAMS};
use rand::{CryptoRng, Rng};
use reqwest::StatusCode;
use uuid::Uuid;
use world_id_primitives::circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput};
use world_id_primitives::oprf::OprfRequestAuthV1;
use world_id_primitives::proof::SingleProofInput;

use world_id_primitives::{Credential, FieldElement, TREE_DEPTH};

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

pub mod nonblocking;

/// Helper function to compute the claims hash for a credential.
/// TODO: Move to primitives.
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

const QUERY_GRAPH_BYTES: &[u8] = include_bytes!("../../../circom/OPRFQueryGraph.bin");
const NULLIFIER_GRAPH_BYTES: &[u8] = include_bytes!("../../../circom/OPRFNullifierGraph.bin");

#[cfg(feature = "embed-zkeys")]
const QUERY_ZKEY_BYTES: &[u8] = include_bytes!("../../../circom/OPRFQuery.arks.zkey");
#[cfg(feature = "embed-zkeys")]
const NULLIFIER_ZKEY_BYTES: &[u8] = include_bytes!("../../../circom/OPRFNullifier.arks.zkey");

/// The SHA-256 fingerprint of the OPRFQuery ZKey.
pub const QUERY_ZKEY_FINGERPRINT: &str =
    "5796f71d0a2b70878a96eb0e0839e31c4f532e660258c3d0bd32047de00fbe02";
/// The SHA-256 fingerprint of the OPRFNullifier ZKey.
pub const NULLIFIER_ZKEY_FINGERPRINT: &str =
    "892f3f46e80330d4f69df776e3ed74383dea127658516182751984ad6a7f4f59";

/// The SHA-256 fingerprint of the OPRFQuery witness graph.
pub const QUERY_GRAPH_FINGERPRINT: &str =
    "ac4caabf7d35a3424f49b627d213a19f17c7572743370687befd3fa8f82610a3";
/// The SHA-256 fingerprint of the OPRFNullifier witness graph.
pub const NULLIFIER_GRAPH_FINGERPRINT: &str =
    "e6d818a0d6a76e98efbe35fba4664fcea33afc0da663041571c8d59c7a5f0fa0";

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
    /// Provided public key index is invalid or out of bounds.
    #[error("Index in public key is invalid or out of bounds.")]
    InvalidPublicKeyIndex,
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    /// Catch-all for other internal errors.
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}

/// A signed OPRF query ready.
///
/// This struct holds all information needed to initiate OPRF sessions:
/// - `request_id`: Unique identifier for this query/request.
/// - `oprf_request`: The fully formed [`OprfRequest`] including the
///   blinded query point and Groth16 proof.
/// - `blinded_request`: The result of blinding the query with the user's key.
/// - `query_input`: Input data for the OPRFQuery proof.
/// - `blinding_factor`: The hash of the query used in proofs.
pub struct SignedOprfQuery {
    request_id: Uuid,
    oprf_request: OprfRequest<OprfRequestAuthV1>,
    blinded_request: BlindedOprfRequest,
    query_input: QueryProofCircuitInput<TREE_DEPTH>,
    blinding_factor: BlindingFactor,
}

/// Holds information about active OPRF sessions with multiple peers.
///
/// Tracks the peer services, their party IDs, and the partial DLog equality
/// commitments received from each peer.
pub struct OprfSessions {
    services: Vec<String>,
    party_ids: Vec<PartyId>,
    commitments: Vec<PartialDLogCommitmentsShamir>,
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
/// - `blinding_factor`: The hash of the query used in proofs.
/// - `rp_nullifier_key`: The RP-specific nullifier public-key.
pub struct Challenge {
    request_id: Uuid,
    challenge_request: ChallengeRequest,
    blinded_request: BlindedOprfRequest,
    blinded_response: ark_babyjubjub::EdwardsAffine,
    query_input: QueryProofCircuitInput<TREE_DEPTH>,
    blinding_factor: BlindingFactor,
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
    pub fn get_request(&self) -> OprfRequest<OprfRequestAuthV1> {
        self.oprf_request.clone()
    }

    /// Returns the [`QueryProofCircuitInput`] that was committed to in the query proof.
    pub fn query_input(&self) -> &QueryProofCircuitInput<TREE_DEPTH> {
        &self.query_input
    }

    /// Returns the [`BlindingFactor`] for this signed query
    pub fn blinding_factor(&self) -> &BlindingFactor {
        &self.blinding_factor
    }
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the embedded keys in the binary.
#[cfg(feature = "embed-zkeys")]
pub fn load_embedded_nullifier_material() -> CircomGroth16Material {
    build_nullifier_builder()
        .build_from_bytes(NULLIFIER_ZKEY_BYTES, NULLIFIER_GRAPH_BYTES)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the query proof from the embedded keys in the binary.
#[cfg(feature = "embed-zkeys")]
pub fn load_embedded_query_material() -> CircomGroth16Material {
    build_query_builder()
        .build_from_bytes(QUERY_ZKEY_BYTES, QUERY_GRAPH_BYTES)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided reader.
pub fn load_nullifier_material_from_reader(
    zkey: impl Read,
    graph: impl Read,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_nullifier_builder().build_from_reader(zkey, graph)?)
}

/// Loads the [`CircomGroth16Material`] for the query proof from the provided reader.
pub fn load_query_material_from_reader(
    zkey: impl Read,
    graph: impl Read,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_query_builder().build_from_reader(zkey, graph)?)
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided path.
pub fn load_nullifier_material_from_paths(
    zkey: impl AsRef<Path>,
    graph: impl AsRef<Path>,
) -> CircomGroth16Material {
    build_nullifier_builder()
        .build_from_paths(zkey, graph)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided path.
pub fn load_query_material_from_paths(
    zkey: impl AsRef<Path>,
    graph: impl AsRef<Path>,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_query_builder().build_from_paths(zkey, graph)?)
}

fn build_nullifier_builder() -> CircomGroth16MaterialBuilder {
    CircomGroth16MaterialBuilder::new()
        .fingerprint_zkey(NULLIFIER_ZKEY_FINGERPRINT.into())
        .fingerprint_graph(NULLIFIER_GRAPH_FINGERPRINT.into())
        .bbf_num_2_bits_helper()
        .bbf_inv()
        .bbf_legendre()
        .bbf_sqrt_input()
        .bbf_sqrt_unchecked()
}

fn build_query_builder() -> CircomGroth16MaterialBuilder {
    CircomGroth16MaterialBuilder::new()
        .fingerprint_zkey(QUERY_ZKEY_FINGERPRINT.into())
        .fingerprint_graph(QUERY_GRAPH_FINGERPRINT.into())
        .bbf_num_2_bits_helper()
        .bbf_inv()
        .bbf_legendre()
        .bbf_sqrt_input()
        .bbf_sqrt_unchecked()
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
/// * `query_material` - Groth16 material (proving key and matrices) used for the query proof.
/// * `args` - [`SingleProofInput`] containing all input data (credentials, Merkle membership, query, keys, signal, etc.).
/// * `private_key` - The user's private key for signing the blinded query.
/// * `nullifier_material` - Groth16 material (proving key and matrices) used for the nullifier proof.
/// * `rng` - A cryptographically secure random number generator.
///
/// # Returns
///
/// On success, returns a tuple:
/// 1. `Proof<Bn254>` – the generated nullifier proof,
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
    query_material: &CircomGroth16Material,
    nullifier_material: &CircomGroth16Material,
    args: SingleProofInput<TREE_DEPTH>,
    private_key: &eddsa_babyjubjub::EdDSAPrivateKey,
    rng: &mut R,
) -> Result<(
    Proof<Bn254>,
    Vec<ark_babyjubjub::Fq>,
    ark_babyjubjub::Fq,
    ark_babyjubjub::Fq,
)> {
    let request_id = Uuid::new_v4();

    let signed_query = sign_oprf_query(&args, query_material, private_key, request_id, rng)?;

    let oprf_rp_nullifier_key = OprfRpNullifierKey::new(args.rp_nullifier_key.into_inner());

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
        *args.signal_hash,
        *args.rp_session_id_r_seed,
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
/// * `args` - [`SingleProofInput`] containing all input data (credentials, Merkle membership, query, keys, signal, etc.).
/// * `query_material` - Groth16 proving key and constraint matrices for query proof.
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
        .ok_or_else(|| Error::InternalError(eyre::eyre!("Credential not signed")))?;

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
        challenge_request: ChallengeRequest {
            request_id: query.request_id,
            challenge,
            rp_identifier: NullifierShareIdentifier {
                rp_id: query.oprf_request.rp_identifier.rp_id,
                share_epoch: query.oprf_request.rp_identifier.share_epoch,
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
    dlog_proof
        .verify(
            challenges.rp_nullifier_key.inner(),
            challenges.blinded_request.blinded_query(),
            challenges.blinded_response,
            ark_babyjubjub::EdwardsAffine::generator(),
        )
        .map_err(|_| Error::InvalidDLogProof)?;

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
