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

use ark_bn254::Bn254;
use groth16_material::Groth16Error;
use rand::{CryptoRng, Rng};
use std::{io::Read, path::Path};
use world_id_primitives::{
    Credential, FieldElement, TREE_DEPTH, circuit_inputs::NullifierProofCircuitInput,
};
use world_id_request::RequestItem;

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

use crate::nullifier::OprfNullifier;

pub(crate) const OPRF_PROOF_DS: &[u8] = b"World ID Proof";

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
const QUERY_GRAPH_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/OPRFQueryGraph.bin"));

#[cfg(all(feature = "embed-zkeys", docsrs))]
const QUERY_GRAPH_BYTES: &[u8] = &[];

#[cfg(all(feature = "embed-zkeys", not(docsrs)))]
const NULLIFIER_GRAPH_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/OPRFNullifierGraph.bin"));

#[cfg(all(feature = "embed-zkeys", docsrs))]
const NULLIFIER_GRAPH_BYTES: &[u8] = &[];

#[cfg(all(feature = "embed-zkeys", not(feature = "compress-zkeys"), not(docsrs)))]
const QUERY_ZKEY_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/OPRFQuery.arks.zkey"));

#[cfg(all(feature = "compress-zkeys", not(docsrs)))]
const QUERY_ZKEY_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/OPRFQuery.arks.zkey.compressed"));

#[cfg(docsrs)]
const QUERY_ZKEY_BYTES: &[u8] = &[];

#[cfg(all(feature = "embed-zkeys", not(feature = "compress-zkeys"), not(docsrs)))]
const NULLIFIER_ZKEY_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/OPRFNullifier.arks.zkey"));

#[cfg(all(feature = "compress-zkeys", not(docsrs)))]
const NULLIFIER_ZKEY_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/OPRFNullifier.arks.zkey.compressed"
));

#[cfg(docsrs)]
const NULLIFIER_ZKEY_BYTES: &[u8] = &[];

/// Error type for OPRF operations and proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Error originating from `oprf_client`.
    #[error(transparent)]
    OprfError(#[from] taceo_oprf::client::Error),
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
/// from the embedded keys in the binary without caching.
///
/// # Returns
/// The nullifier material.
///
/// # Errors
/// Will return an error if the zkey file cannot be loaded.
#[cfg(feature = "embed-zkeys")]
pub fn load_embedded_nullifier_material(
    cache_dir: Option<impl AsRef<Path>>,
) -> eyre::Result<CircomGroth16Material> {
    let nullifier_zkey_bytes = load_embedded_nullifier_zkey(cache_dir)?;
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
#[cfg(feature = "embed-zkeys")]
pub fn load_embedded_query_material(
    cache_dir: Option<impl AsRef<Path>>,
) -> eyre::Result<CircomGroth16Material> {
    let query_zkey_bytes = load_embedded_query_zkey(cache_dir)?;
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

/// Loads the query zkey from embedded bytes,
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
#[cfg(feature = "embed-zkeys")]
fn load_embedded_query_zkey(cache_dir: Option<impl AsRef<Path>>) -> eyre::Result<Vec<u8>> {
    #[cfg(feature = "compress-zkeys")]
    {
        load_embedded_compressed_zkey(cache_dir, "OPRFQuery.arks.zkey", QUERY_ZKEY_BYTES)
    }

    #[cfg(all(feature = "embed-zkeys", not(feature = "compress-zkeys")))]
    {
        Ok(QUERY_ZKEY_BYTES.to_vec())
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
#[cfg(feature = "embed-zkeys")]
fn load_embedded_nullifier_zkey(cache_dir: Option<impl AsRef<Path>>) -> eyre::Result<Vec<u8>> {
    #[cfg(feature = "compress-zkeys")]
    {
        load_embedded_compressed_zkey(cache_dir, "OPRFNullifier.arks.zkey", NULLIFIER_ZKEY_BYTES)
    }

    #[cfg(all(feature = "embed-zkeys", not(feature = "compress-zkeys")))]
    {
        Ok(NULLIFIER_ZKEY_BYTES.to_vec())
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
    match std::fs::read(&path) {
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
            std::fs::create_dir_all(&cache_dir)?;
            std::fs::write(&path, &uncompressed)?;
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

/// FIXME. Description.
/// Generates the Groth16 nullifier proof ....
///
/// Internally can be a Session Proof or Uniqueness Proof
///
/// # Errors
///
/// Returns [`ProofError`] if proof generation or verification fails.
#[allow(clippy::too_many_arguments)]
pub fn generate_nullifier_proof<R: Rng + CryptoRng>(
    nullifier_material: &CircomGroth16Material,
    rng: &mut R,
    credential: &Credential,
    credential_sub_blinding_factor: FieldElement,
    oprf_nullifier: OprfNullifier,
    request_item: &RequestItem,
    session_id: Option<FieldElement>,
    session_id_r_seed: FieldElement,
    timestamp: u64,
) -> Result<
    (
        ark_groth16::Proof<Bn254>,
        Vec<ark_babyjubjub::Fq>,
        ark_babyjubjub::Fq,
    ),
    ProofError,
> {
    let cred_signature = credential
        .signature
        .clone()
        .ok_or_else(|| ProofError::InternalError(eyre::eyre!("Credential not signed")))?;

    let nullifier_input = NullifierProofCircuitInput::<TREE_DEPTH> {
        query_input: oprf_nullifier.query_proof_input,
        issuer_schema_id: credential.issuer_schema_id.into(),
        cred_pk: credential.issuer.pk,
        cred_hashes: [*credential.claims_hash()?, *credential.associated_data_hash],
        cred_genesis_issued_at: credential.genesis_issued_at.into(),
        cred_genesis_issued_at_min: request_item.genesis_issued_at_min.unwrap_or(0).into(),
        cred_expires_at: credential.expires_at.into(),
        cred_id: credential.id.into(),
        cred_sub_blinding_factor: *credential_sub_blinding_factor,
        cred_s: cred_signature.s,
        cred_r: cred_signature.r,
        id_commitment_r: *session_id_r_seed,
        id_commitment: *session_id.unwrap_or(FieldElement::ZERO),
        dlog_e: oprf_nullifier.verifiable_oprf_output.dlog_proof.e,
        dlog_s: oprf_nullifier.verifiable_oprf_output.dlog_proof.s,
        oprf_pk: oprf_nullifier
            .verifiable_oprf_output
            .oprf_public_key
            .inner(),
        oprf_response_blinded: oprf_nullifier.verifiable_oprf_output.blinded_response,
        oprf_response: oprf_nullifier.verifiable_oprf_output.unblinded_response,
        signal_hash: *request_item.signal_hash(),
        current_timestamp: timestamp.into(),
    };

    let (proof, public) = nullifier_material.generate_proof(&nullifier_input, rng)?;
    nullifier_material.verify_proof(&proof, &public)?;

    let nullifier = public[0];

    // Verify that the computed nullifier matches the OPRF output.
    if nullifier != oprf_nullifier.verifiable_oprf_output.output {
        return Err(ProofError::InternalError(eyre::eyre!(
            "Computed nullifier does not match OPRF output"
        )));
    }

    Ok((proof, public, nullifier))
}
