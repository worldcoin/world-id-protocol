//! Internal proof generation for the World ID Protocol.
//!
//! Provides functionality for generating ZKPs (zero-knowledge proofs), including
//! Uniqueness Proofs (internally also called Nullifier Proofs `π2`) and Session Proofs. It
//! also contains internal proof computation such as Query Proofs `π1`.
//!
//! The proof generation workflow for Uniqueness Proofs consists of:
//! 1. Loading circuit proving material (zkeys and witness graphs)
//! 2. Signing OPRF queries and generating a Query Proof `π1`
//! 3. Interacting with OPRF services to obtain challenge responses
//! 4. Verifying `DLog` equality proofs from OPRF nodes
//! 5. Generating the final Uniqueness Proof `π2`

use ark_ff::PrimeField as _;
use circom_types::ark_bn254::Bn254;
use circom_types::groth16::Proof;
use groth16_material::Groth16Error;
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};
use std::io::Read;
use std::path::Path;
use taceo_oprf_client::Connector;
use taceo_oprf_core::oprf::BlindingFactor;
use taceo_oprf_types::ShareEpoch;
use world_id_primitives::circuit_inputs::QueryProofCircuitInput;
use world_id_primitives::oprf::OprfRequestAuthV1;
use world_id_primitives::rp::RpId;
use world_id_primitives::{circuit_inputs::NullifierProofCircuitInput, proof::SingleProofInput};
use world_id_primitives::{FieldElement, TREE_DEPTH};

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

use crate::HashableCredential;

const OPRF_QUERY_DS: &[u8] = b"World ID Query";
const OPRF_PROOF_DS: &[u8] = b"World ID Proof";

/// The SHA-256 fingerprint of the `OPRFQuery` `ZKey`.
pub const QUERY_ZKEY_FINGERPRINT: &str =
    "ee106cc2d213cca77cf7372c69851ca330f4f3fc7bff481ec2285a9f9494c041";
/// The SHA-256 fingerprint of the `OPRFNullifier` `ZKey`.
pub const NULLIFIER_ZKEY_FINGERPRINT: &str =
    "b570ceef9c8c71f5559da8d3fd03a09ae27d93634d8dff1eec24235dc61e660f";

/// The SHA-256 fingerprint of the `OPRFQuery` witness graph.
pub const QUERY_GRAPH_FINGERPRINT: &str =
    "a22f17b20d65c88ffe6cca14863c42933ce6bbf28a56c902197e187d0e1268ef";
/// The SHA-256 fingerprint of the `OPRFNullifier` witness graph.
pub const NULLIFIER_GRAPH_FINGERPRINT: &str =
    "5472d0b875f5145f66fd75d94fa24dd34bd54feb130ff96e4a323ca68cfc0c2e";

#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const QUERY_GRAPH_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/OPRFQueryGraph.bin"));
#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const NULLIFIER_GRAPH_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/OPRFNullifierGraph.bin"));

#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const QUERY_ZKEY_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/OPRFQuery.arks.zkey"));
#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const NULLIFIER_ZKEY_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/OPRFNullifier.arks.zkey"));

/// Error type for OPRF operations and proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Error originating from `oprf_client`.
    #[error(transparent)]
    OprfError(#[from] taceo_oprf_client::Error),
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    /// Catch-all for other internal errors.
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}

// ============================================================================
// Circuit Material Loaders
// ============================================================================

/// Loads the [`CircomGroth16Material`] for the uniqueness proof (internally also nullifier proof)
/// from the embedded keys in the binary.
///
/// # Panics
/// Will panic if the embedded material cannot be loaded or verified.
#[must_use]
#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
pub fn load_embedded_nullifier_material() -> CircomGroth16Material {
    build_nullifier_builder()
        .build_from_bytes(NULLIFIER_ZKEY_BYTES, NULLIFIER_GRAPH_BYTES)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the query proof from the embedded keys in the binary.
///
/// # Panics
/// Will panic if the embedded material cannot be loaded or verified.
#[must_use]
#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
pub fn load_embedded_query_material() -> CircomGroth16Material {
    build_query_builder()
        .build_from_bytes(QUERY_ZKEY_BYTES, QUERY_GRAPH_BYTES)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the uniqueness proof (internally also nullifier proof)
/// from the embedded keys in the binary.
#[cfg(docsrs)]
#[must_use]
pub fn load_embedded_nullifier_material() -> CircomGroth16Material {
    // TODO: This is a stub for docs.rs compilation only
    todo!(
        "load_embedded_nullifier_material is not available on docs.rs - use load_nullifier_material_from_paths or load_nullifier_material_from_reader instead"
    )
}

/// Loads the [`CircomGroth16Material`] for the query proof from the embedded keys in the binary.
#[cfg(docsrs)]
#[must_use]
pub fn load_embedded_query_material() -> CircomGroth16Material {
    // TODO: This is a stub for docs.rs compilation only
    todo!(
        "load_embedded_query_material is not available on docs.rs - use load_query_material_from_paths or load_query_material_from_reader instead"
    )
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided reader.
///
/// # Errors
/// Will return an error if the material cannot be loaded or verified.
pub fn load_nullifier_material_from_reader(
    zkey: impl Read,
    graph: impl Read,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_nullifier_builder().build_from_reader(zkey, graph)?)
}

/// Loads the [`CircomGroth16Material`] for the query proof from the provided reader.
///
/// # Errors
/// Will return an error if the material cannot be loaded or verified.
pub fn load_query_material_from_reader(
    zkey: impl Read,
    graph: impl Read,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_query_builder().build_from_reader(zkey, graph)?)
}

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided paths.
///
/// # Panics
/// Will panic if the material cannot be loaded or verified.
pub fn load_nullifier_material_from_paths(
    zkey: impl AsRef<Path>,
    graph: impl AsRef<Path>,
) -> CircomGroth16Material {
    build_nullifier_builder()
        .build_from_paths(zkey, graph)
        .expect("works when loading embedded groth16-material")
}

/// Loads the [`CircomGroth16Material`] for the query proof from the provided paths.
///
/// # Errors
/// Will return an error if the material cannot be loaded or verified.
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

// ============================================================================
// Uniqueness Proof (internally also called nullifier proof) Generation
// ============================================================================

/// Generates a nullifier proof for a given query.
///
/// Full workflow:
/// 1. Signs and blinds the OPRF query using the user's credentials and key material.
/// 2. Initiates sessions with the provided OPRF services and waits for enough responses.
/// 3. Computes the `DLog` equality challenges using Shamir interpolation.
/// 4. Collects the responses and verifies the challenges.
/// 5. Generates the final Groth16 nullifier proof along with public inputs.
///
/// # Arguments
///
/// * `services` - List of OPRF service URLs to contact.
/// * `threshold` - Minimum number of valid peer responses required.
/// * `query_material` - Groth16 material (proving key and matrices) used for the query proof.
/// * `nullifier_material` - Groth16 material (proving key and matrices) used for the nullifier proof.
/// * `args` - [`SingleProofInput`] containing all input data (credentials, Merkle membership, query, keys, signal, etc.).
/// * `private_key` - The user's private key for signing the blinded query.
/// * `connector` - Connector for WebSocket communication with OPRF nodes.
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
/// Returns [`ProofError`] in the following cases:
/// * `InvalidDLogProof` – the `DLog` equality proof could not be verified.
/// * Other errors may propagate from network requests, proof generation, or Groth16 verification.
#[expect(clippy::too_many_arguments)]
pub async fn nullifier<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    query_material: &CircomGroth16Material,
    nullifier_material: &CircomGroth16Material,
    args: SingleProofInput<TREE_DEPTH>,
    private_key: &eddsa_babyjubjub::EdDSAPrivateKey,
    connector: Connector,
    rng: &mut R,
) -> Result<
    (
        Proof<Bn254>,
        Vec<ark_babyjubjub::Fq>,
        ark_babyjubjub::Fq,
        ark_babyjubjub::Fq,
    ),
    ProofError,
> {
    let share_epoch = ShareEpoch::new(args.share_epoch);
    let cred_signature = args
        .credential
        .signature
        .clone()
        .ok_or_else(|| ProofError::InternalError(eyre::eyre!("Credential not signed")))?;
    let query_hash = query_hash(args.inclusion_proof.leaf_index, args.rp_id, args.action);
    let blinding_factor = BlindingFactor::rand(rng);

    let (oprf_request_auth, query_input) = oprf_request_auth(
        &args,
        query_material,
        private_key,
        query_hash,
        &blinding_factor,
        rng,
    )?;

    let verifiable_oprf_output = taceo_oprf_client::distributed_oprf(
        services,
        threshold,
        args.oprf_public_key,
        args.oprf_key_id,
        share_epoch,
        query_hash,
        blinding_factor,
        ark_babyjubjub::Fq::from_be_bytes_mod_order(OPRF_PROOF_DS),
        oprf_request_auth,
        connector,
    )
    .await?;

    let nullifier_input = NullifierProofCircuitInput::<TREE_DEPTH> {
        query_input,
        issuer_schema_id: args.credential.issuer_schema_id.into(),
        cred_pk: args.credential.issuer.pk,
        cred_hashes: [
            *args.credential.claims_hash()?,
            *args.credential.associated_data_hash,
        ],
        cred_genesis_issued_at: args.credential.genesis_issued_at.into(),
        cred_genesis_issued_at_min: args.genesis_issued_at_min.into(),
        cred_expires_at: args.credential.expires_at.into(),
        cred_id: args.credential.id.into(),
        cred_sub_blinding_factor: *args.credential_sub_blinding_factor,
        cred_s: cred_signature.s,
        cred_r: cred_signature.r,
        id_commitment_r: *args.session_id_r_seed,
        dlog_e: verifiable_oprf_output.dlog_proof.e,
        dlog_s: verifiable_oprf_output.dlog_proof.s,
        oprf_pk: args.oprf_public_key.inner(),
        oprf_response_blinded: verifiable_oprf_output.blinded_response,
        oprf_response: verifiable_oprf_output.unblinded_response,
        signal_hash: *args.signal_hash,
        current_timestamp: args.current_timestamp.into(),
    };

    let (proof, public) = nullifier_material.generate_proof(&nullifier_input, rng)?;
    nullifier_material.verify_proof(&proof, &public)?;

    // 2 outputs, 0 is id_commitment, 1 is nullifier
    let id_commitment = public[0];
    let nullifier = public[1];

    // Verify that the computed nullifier matches the OPRF output, this should never fail unless there is a bug
    if nullifier != verifiable_oprf_output.output {
        return Err(ProofError::InternalError(eyre::eyre!(
            "Computed nullifier does not match OPRF output"
        )));
    }

    Ok((proof.into(), public, nullifier, id_commitment))
}

/// Helper function to generate the OPRF request authentication structure and query proof.
///
/// # Arguments
///
/// * `args` - [`SingleProofInput`] containing all input data (credentials, Merkle membership, query, keys, signal, etc.).
/// * `query_material` - Groth16 material (proving key and matrices) used
///   for the query proof.
/// * `private_key` - The user's private key for signing the blinded query.
/// * `query_hash` - The hash of the OPRF query.
/// * `blinding_factor` - The blinding factor used for the OPRF query
/// * `rng` - A cryptographically secure random number generator.
///
/// # Returns
///
/// On success, returns a tuple:
/// 1. `OprfRequestAuthV1` – the authentication structure for the OPRF request.
/// 2. `QueryProofCircuitInput<TREE_DEPTH>` – the input used for generating the query proof.
///
/// # Errors
///
/// Returns [`ProofError`] in the following cases:
/// * `InvalidDLogProof` – the `DLog` equality proof could not be verified.
/// * Other errors may propagate from network requests, proof generation, or Groth16 verification.
pub fn oprf_request_auth<R: Rng + CryptoRng>(
    args: &SingleProofInput<TREE_DEPTH>,
    query_material: &CircomGroth16Material,
    private_key: &eddsa_babyjubjub::EdDSAPrivateKey,
    query_hash: ark_babyjubjub::Fq,
    blinding_factor: &BlindingFactor,
    rng: &mut R,
) -> Result<(OprfRequestAuthV1, QueryProofCircuitInput<TREE_DEPTH>), ProofError> {
    let signature = private_key.sign(query_hash);

    let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] = args.inclusion_proof.siblings.map(|s| *s);

    let query_input = QueryProofCircuitInput::<TREE_DEPTH> {
        pk: args.key_set.as_affine_array(),
        pk_index: args.key_index.into(),
        s: signature.s,
        r: signature.r,
        merkle_root: *args.inclusion_proof.root,
        depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
        mt_index: args.inclusion_proof.leaf_index.into(),
        siblings,
        beta: blinding_factor.beta(),
        rp_id: *FieldElement::from(args.rp_id),
        action: *args.action,
        nonce: *args.nonce,
    };

    tracing::debug!("generate query proof");
    let (proof, public_inputs) = query_material.generate_proof(&query_input, rng)?;
    query_material.verify_proof(&proof, &public_inputs)?;

    let auth = OprfRequestAuthV1 {
        proof: proof.into(),
        action: *args.action,
        nonce: *args.nonce,
        merkle_root: *args.inclusion_proof.root,
        current_time_stamp: args.current_timestamp,
        signature: args.rp_signature,
        rp_id: args.rp_id,
    };

    Ok((auth, query_input))
}

/// Helper function to compute the query hash for a given account, RP ID, and action.
#[must_use]
pub fn query_hash(leaf_index: u64, rp_id: RpId, action: FieldElement) -> ark_babyjubjub::Fq {
    let input = [
        ark_babyjubjub::Fq::from_be_bytes_mod_order(OPRF_QUERY_DS),
        leaf_index.into(),
        *FieldElement::from(rp_id),
        *action,
    ];
    let poseidon2_4: Poseidon2<ark_babyjubjub::Fq, 4, 5> = Poseidon2::default();
    poseidon2_4.permutation(&input)[1]
}
