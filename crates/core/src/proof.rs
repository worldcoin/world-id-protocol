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
use circom_types::{ark_bn254::Bn254, groth16::Proof};
use groth16_material::Groth16Error;
use poseidon2::Poseidon2;
use rand::{CryptoRng, Rng};
use std::{
    fs::{self},
    io::Read,
    path::Path,
};
use taceo_oprf_client::Connector;
use taceo_oprf_core::oprf::BlindingFactor;
use taceo_oprf_types::ShareEpoch;
use world_id_primitives::{
    FieldElement, TREE_DEPTH,
    circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput},
    oprf::OprfRequestAuthV1,
    proof::SingleProofInput,
    rp::RpId,
};

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

use crate::HashableCredential;

const OPRF_QUERY_DS: &[u8] = b"World ID Query";
const OPRF_PROOF_DS: &[u8] = b"World ID Proof";

/// The SHA-256 fingerprint of the `OPRFQuery` `ZKey`.
pub const QUERY_ZKEY_FINGERPRINT: &str =
    "292483d5631c28f15613b26bee6cf62a8cc9bbd74a97f375aea89e4dfbf7a10f";
/// The SHA-256 fingerprint of the `OPRFNullifier` `ZKey`.
pub const NULLIFIER_ZKEY_FINGERPRINT: &str =
    "14bd468c7fc6e91e48fa776995c267493845d93648a4c1ee24c2567b18b1795a";

/// The SHA-256 fingerprint of the `OPRFQuery` witness graph.
pub const QUERY_GRAPH_FINGERPRINT: &str =
    "6b0cb90304c510f9142a555fe2b7cf31b9f68f6f37286f4471fd5d03e91da311";
/// The SHA-256 fingerprint of the `OPRFNullifier` witness graph.
pub const NULLIFIER_GRAPH_FINGERPRINT: &str =
    "c1d951716e3b74b72e4ea0429986849cadc43cccc630a7ee44a56a6199a66b9a";

#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const QUERY_GRAPH_BYTES: &[u8] = include_bytes!("../../../circom/OPRFQueryGraph.bin");

#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const NULLIFIER_GRAPH_BYTES: &[u8] = include_bytes!("../../../circom/OPRFNullifierGraph.bin");

#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const QUERY_ZKEY_BYTES: &[u8] = if cfg!(feature = "compress-zkeys") {
    include_bytes!("../../../circom/OPRFQuery.arks.zkey.compressed")
} else {
    include_bytes!("../../../circom/OPRFQuery.arks.zkey")
};

#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const NULLIFIER_ZKEY_BYTES: &[u8] = if cfg!(feature = "compress-zkeys") {
    include_bytes!("../../../circom/OPRFNullifier.arks.zkey.compressed")
} else {
    include_bytes!("../../../circom/OPRFNullifier.arks.zkey")
};

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
/// from the optional zkey file or from embedded keys in the binary.
///
/// # Arguments
/// * `nullifier_zkey` - Optional path to the nullifier zkey file. If `None`, will attempt to load from embedded bytes.
/// * `cache_dir` - Optional directory to cache the uncompressed zkey.
///
/// # Returns
/// The uncompressed nullifier zkey bytes.
///
/// # Errors
/// Will return an error if the zkey file cannot be loaded.
pub fn load_nullifier_material(
    nullifier_zkey: Option<impl AsRef<Path>>,
    cache_dir: Option<impl AsRef<Path>>,
) -> eyre::Result<CircomGroth16Material> {
    let nullifier_zkey_bytes = load_nullifier_zkey(nullifier_zkey, cache_dir)?;
    Ok(build_nullifier_builder().build_from_bytes(&nullifier_zkey_bytes, NULLIFIER_GRAPH_BYTES)?)
}

/// Loads the [`CircomGroth16Material`] for the query proof from the optional zkey file or from the embedded keys in the binary.
///
/// # Arguments
/// * `query_zkey` - Optional path to the query zkey file. If `None`, will attempt to load from embedded bytes.
/// * `cache_dir` - Optional directory to cache the uncompressed zkey.
///
/// # Returns
/// The uncompressed query zkey bytes.
///
/// # Errors
/// Will return an error if the zkey file cannot be loaded.
pub fn load_query_material(
    query_zkey: Option<impl AsRef<Path>>,
    cache_dir: Option<impl AsRef<Path>>,
) -> eyre::Result<CircomGroth16Material> {
    let query_zkey_bytes = load_query_zkey(query_zkey, cache_dir)?;
    Ok(build_query_builder().build_from_bytes(&query_zkey_bytes, QUERY_GRAPH_BYTES)?)
}

/// Loads the [`CircomGroth16Material`] for the uniqueness proof (internally also nullifier proof)
/// from the embedded keys in the binary without caching.
///
/// # Returns
/// The nullifier material.
///
/// # Errors
/// Will return an error if the zkey file cannot be loaded.
// #[cfg(all(feature = "embed-zkeys", not(feature = "compress-zkeys")))]
pub fn load_embedded_nullifier_material() -> eyre::Result<CircomGroth16Material> {
    let nullifier_zkey_bytes = load_nullifier_zkey(
        Option::<std::path::PathBuf>::None,
        Option::<std::path::PathBuf>::None,
    )?;
    Ok(build_nullifier_builder().build_from_bytes(&nullifier_zkey_bytes, NULLIFIER_GRAPH_BYTES)?)
}

/// Loads the [`CircomGroth16Material`] for the uniqueness proof (internally also query proof)
/// from the optional zkey file or from embedded keys in the binary.
///
/// # Returns
/// The query material
///
/// # Errors
/// Will return an error if the zkey file cannot be loaded.
// #[cfg(all(feature = "embed-zkeys", not(feature = "compress-zkeys")))]
pub fn load_embedded_query_material() -> eyre::Result<CircomGroth16Material> {
    let query_zkey_bytes = load_query_zkey(
        Option::<std::path::PathBuf>::None,
        Option::<std::path::PathBuf>::None,
    )?;
    Ok(build_query_builder().build_from_bytes(&query_zkey_bytes, QUERY_GRAPH_BYTES)?)
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

/// Loads the query zkey from the provided path, or from embedded bytes,
/// decompressing and caching it on disk if necessary.
///
/// # Arguments
/// * `query_zkey` - Optional path to the query zkey file. If `None`, will attempt to load from embedded bytes.
/// * `cache_dir` - Optional directory to cache the uncompressed zkey.
///
/// # Returns
/// The uncompressed query zkey bytes.
///
/// # Errors
/// Will return an error if the zkey file cannot be loaded.
#[allow(unused_variables)]
fn load_query_zkey(
    query_zkey: Option<impl AsRef<Path>>,
    cache_dir: Option<impl AsRef<Path>>,
) -> eyre::Result<Vec<u8>> {
    if let Some(path) = query_zkey {
        Ok(fs::read(path)?)
    } else if cfg!(feature = "embed-zkeys") {
        #[cfg(feature = "compress-zkeys")]
        {
            load_embedded_compressed_zkey(cache_dir, "OPRFQuery.arks.zkey", QUERY_ZKEY_BYTES)
        }

        #[cfg(not(feature = "compress-zkeys"))]
        {
            Ok(QUERY_ZKEY_BYTES.to_vec())
        }
    } else {
        Err(eyre::eyre!(
            "No query zkey provided and embedded zkeys are not available"
        ))
    }
}

/// Loads the nullifier zkey from the provided path, or from embedded bytes,
/// decompressing and caching it on disk if necessary.
///
/// # Arguments
/// * `nullifier_zkey` - Optional path to the nullifier zkey file. If `None`, will attempt to load from embedded bytes.
/// * `cache_dir` - Optional directory to cache the uncompressed zkey.
///
/// # Returns
/// The uncompressed nullifier zkey bytes.
///
/// # Errors
/// Will return an error if the zkey file cannot be loaded.
#[allow(unused_variables)]
fn load_nullifier_zkey(
    nullifier_zkey: Option<impl AsRef<Path>>,
    cache_dir: Option<impl AsRef<Path>>,
) -> eyre::Result<Vec<u8>> {
    if let Some(path) = nullifier_zkey {
        Ok(fs::read(path)?)
    } else if cfg!(feature = "embed-zkeys") {
        #[cfg(feature = "compress-zkeys")]
        {
            load_embedded_compressed_zkey(
                cache_dir,
                "OPRFNullifier.arks.zkey",
                NULLIFIER_ZKEY_BYTES,
            )
        }

        #[cfg(not(feature = "compress-zkeys"))]
        {
            Ok(NULLIFIER_ZKEY_BYTES.to_vec())
        }
    } else {
        Err(eyre::eyre!(
            "No nullifier zkey provided and embedded zkeys are not available"
        ))
    }
}

/// Loads an embedded compressed zkey, decompressing and caching it on disk if necessary.
///
/// # Arguments
/// * `cache_dir` - Optional directory to cache the uncompressed zkey.
/// * `file_name` - The file name to use for caching.
/// * `bytes` - The compressed zkey bytes.
///
/// # Returns
/// The uncompressed zkey bytes.
///
/// # Errors
/// Will return an error if decompression or file operations fail.
#[cfg(feature = "compress-zkeys")]
fn load_embedded_compressed_zkey(
    cache_dir: Option<impl AsRef<Path>>,
    file_name: &str,
    bytes: &[u8],
) -> eyre::Result<Vec<u8>> {
    let compressed = bytes.to_vec();
    let cache_dir = match cache_dir {
        Some(dir) => dir.as_ref().to_path_buf(),
        None => {
            tracing::warn!(
                "No cache directory provided for uncompressed zkey, using system temp directory"
            );
            let mut dir = std::env::temp_dir();
            dir.push("world-id-zkey-cache");
            dir
        }
    };
    let path = cache_dir.join(file_name);
    match fs::read(&path) {
        Ok(bytes) => Ok(bytes),
        Err(_) => {
            // Decompress and cache
            let zkey =
                <circom_types::groth16::ArkZkey<Bn254> as ark_serialize::CanonicalDeserialize>::deserialize_with_mode(
                    compressed.as_slice(),
                    ark_serialize::Compress::Yes,
                    ark_serialize::Validate::Yes,
                )?;

            let mut uncompressed = Vec::new();
            ark_serialize::CanonicalSerialize::serialize_with_mode(
                &zkey,
                &mut uncompressed,
                ark_serialize::Compress::No,
            )?;
            fs::create_dir_all(&cache_dir)?;
            fs::write(&path, &uncompressed)?;
            Ok(uncompressed)
        }
    }
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
) -> Result<(Proof<Bn254>, Vec<ark_babyjubjub::Fq>, ark_babyjubjub::Fq), ProofError> {
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
        id_commitment: *args.session_id,
        dlog_e: verifiable_oprf_output.dlog_proof.e,
        dlog_s: verifiable_oprf_output.dlog_proof.s,
        oprf_pk: verifiable_oprf_output.oprf_public_key.inner(),
        oprf_response_blinded: verifiable_oprf_output.blinded_response,
        oprf_response: verifiable_oprf_output.unblinded_response,
        signal_hash: *args.signal_hash,
        current_timestamp: args.current_timestamp.into(),
    };

    let (proof, public) = nullifier_material.generate_proof(&nullifier_input, rng)?;
    nullifier_material.verify_proof(&proof, &public)?;

    let nullifier = public[0];

    // Verify that the computed nullifier matches the OPRF output, this should never fail unless there is a bug
    if nullifier != verifiable_oprf_output.output {
        return Err(ProofError::InternalError(eyre::eyre!(
            "Computed nullifier does not match OPRF output"
        )));
    }

    Ok((proof.into(), public, nullifier))
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
