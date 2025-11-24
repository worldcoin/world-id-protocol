//! Internal proof generation for the World ID Protocol.
//!
//! Provides functionality for generating ZKPs (zero-knowledge proofs), including
//! Uniqueness Proofs (internally also called Nullifier Proofs [`π2`]) and Session Proofs. It
//! also contains internal proof computation such as Query Proofs [`π1`].
//!
//! The proof generation workflow for Uniqueness Proofs consists of:
//! 1. Loading circuit proving material (zkeys and witness graphs)
//! 2. Signing OPRF queries and generating a Query Proof [`π1`]
//! 3. Interacting with OPRF services to obtain challenge responses
//! 4. Verifying `DLog` equality proofs from OPRF nodes
//! 5. Generating the final Nullifier Proof [`π2`]

use crate::oprf::{compute_challenges, sign_oprf_query, ProofError};
use circom_types::ark_bn254::Bn254;
use circom_types::groth16::Proof;
use oprf_types::crypto::RpNullifierKey as OprfRpNullifierKey;
use rand::{CryptoRng, Rng};
use std::io::Read;
use std::path::Path;
use uuid::Uuid;
use world_id_primitives::proof::SingleProofInput;
use world_id_primitives::TREE_DEPTH;

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

/// The SHA-256 fingerprint of the `OPRFQuery` `ZKey`.
pub const QUERY_ZKEY_FINGERPRINT: &str =
    "5796f71d0a2b70878a96eb0e0839e31c4f532e660258c3d0bd32047de00fbe02";
/// The SHA-256 fingerprint of the `OPRFNullifier` `ZKey`.
pub const NULLIFIER_ZKEY_FINGERPRINT: &str =
    "892f3f46e80330d4f69df776e3ed74383dea127658516182751984ad6a7f4f59";

/// The SHA-256 fingerprint of the `OPRFQuery` witness graph.
pub const QUERY_GRAPH_FINGERPRINT: &str =
    "ac4caabf7d35a3424f49b627d213a19f17c7572743370687befd3fa8f82610a3";
/// The SHA-256 fingerprint of the `OPRFNullifier` witness graph.
pub const NULLIFIER_GRAPH_FINGERPRINT: &str =
    "e6d818a0d6a76e98efbe35fba4664fcea33afc0da663041571c8d59c7a5f0fa0";

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

// ============================================================================
// Circuit Material Loaders
// ============================================================================

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the embedded keys in the binary.
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

// Stub implementations for docs.rs
#[cfg(docsrs)]
#[must_use]
pub fn load_embedded_nullifier_material() -> CircomGroth16Material {
    // TODO: This is a stub for docs.rs compilation only
    todo!("load_embedded_nullifier_material is not available on docs.rs - use load_nullifier_material_from_paths or load_nullifier_material_from_reader instead")
}

#[cfg(docsrs)]
#[must_use]
pub fn load_embedded_query_material() -> CircomGroth16Material {
    // TODO: This is a stub for docs.rs compilation only
    todo!("load_embedded_query_material is not available on docs.rs - use load_query_material_from_paths or load_query_material_from_reader instead")
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
// Nullifier Proof Generation
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
/// * `InvalidPublicKeyIndex` – the user key index is out of range.
/// * `InvalidDLogProof` – the `DLog` equality proof could not be verified.
/// * Other errors may propagate from network requests, proof generation, or Groth16 verification.
pub async fn nullifier<R: Rng + CryptoRng>(
    services: &[String],
    threshold: usize,
    query_material: &CircomGroth16Material,
    nullifier_material: &CircomGroth16Material,
    args: SingleProofInput<TREE_DEPTH>,
    private_key: &eddsa_babyjubjub::EdDSAPrivateKey,
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
    let request_id = Uuid::new_v4();

    let signed_query = sign_oprf_query(&args, query_material, private_key, request_id, rng)?;

    let oprf_rp_nullifier_key = OprfRpNullifierKey::new(args.rp_nullifier_key.into_inner());

    let client = reqwest::Client::new();
    let req = signed_query.get_request();
    let sessions = crate::oprf::init_sessions(&client, services, threshold, req).await?;

    let challenges = compute_challenges(signed_query, &sessions, oprf_rp_nullifier_key)?;
    let req = challenges.get_request();
    let responses = crate::oprf::finish_sessions(&client, sessions, req).await?;
    crate::oprf::verify_challenges(
        nullifier_material,
        challenges,
        responses,
        *args.signal_hash,
        *args.rp_session_id_r_seed,
        rng,
    )
}
