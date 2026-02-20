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
    Credential, FieldElement, RequestItem, TREE_DEPTH, circuit_inputs::NullifierProofCircuitInput,
};

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

use crate::nullifier::OprfNullifier;

pub mod errors;

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
const CIRCUIT_ARCHIVE: &[u8] = {
    #[cfg(feature = "zstd-compress-zkeys")]
    {
        include_bytes!(concat!(env!("OUT_DIR"), "/circuit_files.tar.zst"))
    }
    #[cfg(not(feature = "zstd-compress-zkeys"))]
    {
        include_bytes!(concat!(env!("OUT_DIR"), "/circuit_files.tar"))
    }
};

#[cfg(all(feature = "embed-zkeys", docsrs))]
const CIRCUIT_ARCHIVE: &[u8] = &[];

#[cfg(feature = "embed-zkeys")]
#[derive(Clone, Debug)]
pub struct EmbeddedCircuitFiles {
    /// Embedded query witness graph bytes.
    pub query_graph: Vec<u8>,
    /// Embedded nullifier witness graph bytes.
    pub nullifier_graph: Vec<u8>,
    /// Embedded query zkey bytes (decompressed if `compress-zkeys` is enabled).
    pub query_zkey: Vec<u8>,
    /// Embedded nullifier zkey bytes (decompressed if `compress-zkeys` is enabled).
    pub nullifier_zkey: Vec<u8>,
}

#[cfg(feature = "embed-zkeys")]
static CIRCUIT_FILES: std::sync::OnceLock<Result<EmbeddedCircuitFiles, String>> =
    std::sync::OnceLock::new();

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
pub fn load_embedded_nullifier_material() -> eyre::Result<CircomGroth16Material> {
    let files = load_embedded_circuit_files()?;
    load_nullifier_material_from_reader(
        files.nullifier_zkey.as_slice(),
        files.nullifier_graph.as_slice(),
    )
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
pub fn load_embedded_query_material() -> eyre::Result<CircomGroth16Material> {
    let files = load_embedded_circuit_files()?;
    load_query_material_from_reader(files.query_zkey.as_slice(), files.query_graph.as_slice())
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

#[cfg(feature = "embed-zkeys")]
pub fn load_embedded_circuit_files() -> eyre::Result<EmbeddedCircuitFiles> {
    let files = get_circuit_files()?;
    Ok(files.clone())
}

#[cfg(feature = "embed-zkeys")]
fn get_circuit_files() -> eyre::Result<&'static EmbeddedCircuitFiles> {
    let files = CIRCUIT_FILES.get_or_init(|| init_circuit_files().map_err(|e| e.to_string()));
    match files {
        Ok(files) => Ok(files),
        Err(err) => Err(eyre::eyre!(err.clone())),
    }
}

#[cfg(feature = "embed-zkeys")]
fn init_circuit_files() -> eyre::Result<EmbeddedCircuitFiles> {
    use std::io::Read as _;

    use eyre::ContextCompat;

    // Step 1: Decode archive bytes (optional zstd decompression)
    let tar_bytes: Vec<u8> = {
        #[cfg(feature = "zstd-compress-zkeys")]
        {
            zstd::stream::decode_all(CIRCUIT_ARCHIVE)?
        }
        #[cfg(not(feature = "zstd-compress-zkeys"))]
        {
            CIRCUIT_ARCHIVE.to_vec()
        }
    };

    // Step 2: Untar — extract 4 entries by filename
    let mut query_graph = None;
    let mut nullifier_graph = None;
    let mut query_zkey = None;
    let mut nullifier_zkey = None;

    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;

        match name {
            "OPRFQueryGraph.bin" => query_graph = Some(buf),
            "OPRFNullifierGraph.bin" => nullifier_graph = Some(buf),
            n if n.starts_with("OPRFQuery.arks.zkey") => query_zkey = Some(buf),
            n if n.starts_with("OPRFNullifier.arks.zkey") => nullifier_zkey = Some(buf),
            _ => {}
        }
    }

    let query_graph = query_graph.context("OPRFQueryGraph.bin not found in archive")?;
    let nullifier_graph = nullifier_graph.context("OPRFNullifierGraph.bin not found in archive")?;
    #[allow(unused_mut)]
    let mut query_zkey = query_zkey.context("OPRFQuery zkey not found in archive")?;
    #[allow(unused_mut)]
    let mut nullifier_zkey = nullifier_zkey.context("OPRFNullifier zkey not found in archive")?;

    // Step 3: ARK decompress zkeys if compress-zkeys is active
    #[cfg(feature = "compress-zkeys")]
    {
        query_zkey = ark_decompress_zkey(&query_zkey)?;
        nullifier_zkey = ark_decompress_zkey(&nullifier_zkey)?;
    }

    Ok(EmbeddedCircuitFiles {
        query_graph,
        nullifier_graph,
        query_zkey,
        nullifier_zkey,
    })
}

/// ARK-decompresses a zkey.
#[cfg(feature = "compress-zkeys")]
pub fn ark_decompress_zkey(compressed: &[u8]) -> eyre::Result<Vec<u8>> {
    let zkey = <circom_types::groth16::ArkZkey<Bn254> as ark_serialize::CanonicalDeserialize>::deserialize_with_mode(
        compressed,
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes,
    )?;

    let mut uncompressed = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_with_mode(
        &zkey,
        &mut uncompressed,
        ark_serialize::Compress::No,
    )?;
    Ok(uncompressed)
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
    expires_at_min: u64,
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
        // The `current_timestamp` constraint in the circuit is used to specify the minimum expiration time for the credential.
        // The circuit verifies that `current_timestamp < cred_expires_at`.
        current_timestamp: expires_at_min.into(),
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

#[cfg(all(test, feature = "embed-zkeys"))]
mod tests {
    use super::*;

    #[test]
    fn loads_embedded_circuit_files() {
        let files = load_embedded_circuit_files().unwrap();
        assert!(!files.query_graph.is_empty());
        assert!(!files.nullifier_graph.is_empty());
        assert!(!files.query_zkey.is_empty());
        assert!(!files.nullifier_zkey.is_empty());
    }

    #[test]
    fn builds_materials_from_embedded_readers() {
        let files = load_embedded_circuit_files().unwrap();
        load_query_material_from_reader(files.query_zkey.as_slice(), files.query_graph.as_slice())
            .unwrap();
        load_nullifier_material_from_reader(
            files.nullifier_zkey.as_slice(),
            files.nullifier_graph.as_slice(),
        )
        .unwrap();
    }

    #[test]
    fn convenience_embedded_material_loaders_work() {
        load_embedded_query_material().unwrap();
        load_embedded_nullifier_material().unwrap();
    }

    #[cfg(feature = "compress-zkeys")]
    #[test]
    fn ark_decompress_zkey_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
        use circom_types::{ark_bn254::Bn254, groth16::ArkZkey};

        let files = load_embedded_circuit_files().unwrap();
        let zkey = ArkZkey::<Bn254>::deserialize_with_mode(
            files.query_zkey.as_slice(),
            Compress::No,
            Validate::Yes,
        )
        .unwrap();
        let mut compressed = Vec::new();
        zkey.serialize_with_mode(&mut compressed, Compress::Yes)
            .unwrap();

        let decompressed = ark_decompress_zkey(&compressed).unwrap();
        assert_eq!(decompressed, files.query_zkey);
    }
}
