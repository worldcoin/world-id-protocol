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
use std::{collections::HashMap, io::Read, path::Path};
use world_id_primitives::{
    Credential, FieldElement, RequestItem, TREE_DEPTH, circuit_inputs::NullifierProofCircuitInput,
};

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

use crate::nullifier::OprfNullifier;

pub(crate) const OPRF_PROOF_DS: &[u8] = b"World ID Proof";

/// Typed error codes for OPRF node server errors.
///
/// These variants represent the known error categories that OPRF nodes
/// can return in their HTTP response bodies. They are used to classify
/// raw error strings and find consensus among multiple node failures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OprfNodeErrorCode {
    /// Groth16 query proof verification failed.
    InvalidProof,
    /// Provided merkle root doesn't match any known root.
    InvalidMerkleRoot,
    /// Client timestamp too far from server time (nullifier-specific).
    TimestampTooLarge,
    /// Invalid signature error (nullifier-specific).
    InvalidSignature,
    /// Recovered signer doesn't match RP's registered signer (nullifier-specific).
    InvalidSigner,
    /// Nonce/signature replay detected (nullifier-specific).
    DuplicateSignature,
    /// RP ID not registered (nullifier-specific).
    UnknownRp,
    /// RP is deactivated (nullifier-specific).
    RpInactive,
    /// Action field must be zero (credential blinding factor-specific).
    InvalidAction,
    /// Issuer schema not registered (credential blinding factor-specific).
    UnknownSchemaIssuer,
    /// Internal server error with UUID.
    InternalServerError,
    /// Catch-all for unrecognized or miscellaneous server errors.
    Unknown(String),
}

impl std::fmt::Display for OprfNodeErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "invalid proof"),
            Self::InvalidMerkleRoot => write!(f, "invalid merkle root"),
            Self::TimestampTooLarge => write!(f, "timestamp difference too large"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::InvalidSigner => write!(f, "invalid signer"),
            Self::DuplicateSignature => write!(f, "duplicate signature"),
            Self::UnknownRp => write!(f, "unknown RP"),
            Self::RpInactive => write!(f, "RP inactive"),
            Self::InvalidAction => write!(f, "invalid action"),
            Self::UnknownSchemaIssuer => write!(f, "unknown schema issuer"),
            Self::InternalServerError => write!(f, "internal server error"),
            Self::Unknown(msg) => write!(f, "unknown error: {msg}"),
        }
    }
}

/// Classifies a raw OPRF server error message into a typed error code.
///
/// Uses prefix and substring matching to identify known error patterns.
/// Server messages may evolve, so this matching is intentionally flexible.
fn classify_server_error(msg: &str) -> OprfNodeErrorCode {
    let lower = msg.to_lowercase();

    if lower.contains("invalid proof") {
        OprfNodeErrorCode::InvalidProof
    } else if lower.contains("invalid merkle root") {
        OprfNodeErrorCode::InvalidMerkleRoot
    } else if lower.contains("time stamp difference is too large")
        || lower.contains("timestamp difference")
    {
        OprfNodeErrorCode::TimestampTooLarge
    } else if lower.contains("invalid signer") {
        OprfNodeErrorCode::InvalidSigner
    } else if lower.contains("signature") && (lower.contains("invalid") || lower.contains("error"))
    {
        OprfNodeErrorCode::InvalidSignature
    } else if lower.contains("duplicate") && lower.contains("signature") {
        OprfNodeErrorCode::DuplicateSignature
    } else if lower.contains("unknown rp") {
        OprfNodeErrorCode::UnknownRp
    } else if lower.contains("rp") && lower.contains("inactive") {
        OprfNodeErrorCode::RpInactive
    } else if lower.contains("invalid action") {
        OprfNodeErrorCode::InvalidAction
    } else if lower.contains("unknown schema issuer") {
        OprfNodeErrorCode::UnknownSchemaIssuer
    } else if lower.contains("internal server error") || lower.contains("error id=") {
        OprfNodeErrorCode::InternalServerError
    } else {
        OprfNodeErrorCode::Unknown(msg.to_string())
    }
}

/// Finds a consensus error code among OPRF node failures.
///
/// Returns the error code if a majority (> half) of all nodes that returned
/// `ServerError` failures share the same classified error code.
///
/// Non-`ServerError` failures (e.g., `Eof`, network errors) are ignored
/// for consensus purposes.
///
/// Returns `None` if:
/// - There are no `ServerError` failures
/// - No single error code is shared by a majority
fn find_consensus_error(
    node_errors: &HashMap<String, taceo_oprf::client::Error>,
) -> Option<OprfNodeErrorCode> {
    // Classify all ServerError failures
    let mut classified: Vec<OprfNodeErrorCode> = Vec::new();

    for err in node_errors.values() {
        if let taceo_oprf::client::Error::ServerError(msg) = err {
            classified.push(classify_server_error(msg));
        }
    }

    if classified.is_empty() {
        return None;
    }

    // Count occurrences of each error code
    let mut counts: HashMap<OprfNodeErrorCode, usize> = HashMap::new();
    for code in &classified {
        *counts.entry(code.clone()).or_insert(0) += 1;
    }

    // Find the most common error code
    let max_count = counts.values().max().copied()?;
    let majority_threshold = classified.len() / 2;

    // Return the code if it appears in more than half of the classified errors
    if max_count > majority_threshold {
        counts
            .into_iter()
            .find(|(_, count)| *count == max_count)
            .map(|(code, _)| code)
    } else {
        None
    }
}

/// The SHA-256 fingerprint of the `OPRFQuery` `ZKey`.
pub const QUERY_ZKEY_FINGERPRINT: &str =
    "616c98c6ba024b5a4015d3ebfd20f6cab12e1e33486080c5167a4bcfac111798";
/// The SHA-256 fingerprint of the `OPRFNullifier` `ZKey`.
pub const NULLIFIER_ZKEY_FINGERPRINT: &str =
    "4247e6bfe1af211e72d3657346802e1af00e6071fb32429a200f9fc0a25a36f9";

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
    OprfError(taceo_oprf::client::Error),
    /// Not enough OPRF node responses were received to satisfy the threshold.
    ///
    /// Unlike `OprfError`, this variant provides structured per-node error
    /// information so callers can inspect individual failures and decide how
    /// to present or aggregate them.
    ///
    /// When a majority of nodes return the same typed error, `code` reflects
    /// that consensus. Otherwise, it contains a fallback `Unknown` code.
    #[error("OPRF nodes did not reach threshold ({threshold_required} required) — consensus error: {code}; details: {}", format_node_errors(.node_errors))]
    OprfNodeError {
        /// The consensus error code, or `Unknown` if no majority was found.
        code: OprfNodeErrorCode,
        /// Threshold that was required for the OPRF protocol to succeed.
        threshold_required: usize,
        /// Individual `(node_url, error_message)` pairs — one entry per node
        /// that returned an error.  Callers are free to inspect, filter, or
        /// summarise these however they see fit.
        node_errors: Vec<(String, String)>,
    },
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    /// Catch-all for other internal errors.
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}

/// Format node errors for the `Display` impl of `ProofError::OprfNodeError`.
fn format_node_errors(node_errors: &[(String, String)]) -> String {
    if node_errors.is_empty() {
        return "no error details available".to_string();
    }
    node_errors
        .iter()
        .map(|(url, err)| format!("{url}: {err}"))
        .collect::<Vec<_>>()
        .join("; ")
}

impl From<taceo_oprf::client::Error> for ProofError {
    fn from(err: taceo_oprf::client::Error) -> Self {
        match err {
            taceo_oprf::client::Error::NotEnoughOprfResponses(threshold, node_errors_map) => {
                // Attempt to find a consensus error code among the failures
                let code = find_consensus_error(&node_errors_map).unwrap_or_else(|| {
                    OprfNodeErrorCode::Unknown("no consensus among node errors".to_string())
                });

                // Convert the HashMap to a Vec for storage
                let node_errors: Vec<(String, String)> = node_errors_map
                    .into_iter()
                    .map(|(url, e)| (url, e.to_string()))
                    .collect();

                Self::OprfNodeError {
                    code,
                    threshold_required: threshold,
                    node_errors,
                }
            }
            other => Self::OprfError(other),
        }
    }
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
            "OPRFQuery.arks.zkey" => query_zkey = Some(buf),
            "OPRFNullifier.arks.zkey" => nullifier_zkey = Some(buf),
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
        if let Ok(decompressed) = ark_decompress_zkey(&query_zkey) {
            query_zkey = decompressed;
        }
        if let Ok(decompressed) = ark_decompress_zkey(&nullifier_zkey) {
            nullifier_zkey = decompressed;
        }
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

#[cfg(test)]
mod oprf_error_tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_classify_server_error_known_patterns() {
        assert_eq!(
            classify_server_error("invalid proof"),
            OprfNodeErrorCode::InvalidProof
        );
        assert_eq!(
            classify_server_error("invalid merkle root"),
            OprfNodeErrorCode::InvalidMerkleRoot
        );
        assert_eq!(
            classify_server_error("the time stamp difference is too large"),
            OprfNodeErrorCode::TimestampTooLarge
        );
        assert_eq!(
            classify_server_error("invalid signer"),
            OprfNodeErrorCode::InvalidSigner
        );
        assert_eq!(
            classify_server_error("SignatureError: invalid signature"),
            OprfNodeErrorCode::InvalidSignature
        );
        assert_eq!(
            classify_server_error("duplicate signature detected"),
            OprfNodeErrorCode::DuplicateSignature
        );
        assert_eq!(
            classify_server_error("unknown rp: 42"),
            OprfNodeErrorCode::UnknownRp
        );
        assert_eq!(
            classify_server_error("rp is inactive"),
            OprfNodeErrorCode::RpInactive
        );
        assert_eq!(
            classify_server_error("invalid action (must be 0 for now)"),
            OprfNodeErrorCode::InvalidAction
        );
        assert_eq!(
            classify_server_error("unknown schema issuer: 127"),
            OprfNodeErrorCode::UnknownSchemaIssuer
        );
        assert_eq!(
            classify_server_error("An internal server error has occurred. Error ID=abc123"),
            OprfNodeErrorCode::InternalServerError
        );

        // Unknown patterns
        match classify_server_error("something completely different") {
            OprfNodeErrorCode::Unknown(msg) => {
                assert_eq!(msg, "something completely different");
            }
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_find_consensus_error_majority_found() {
        let mut node_errors = HashMap::new();
        node_errors.insert(
            "node1".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );
        node_errors.insert(
            "node2".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );
        node_errors.insert(
            "node3".to_string(),
            taceo_oprf::client::Error::ServerError("invalid merkle root".to_string()),
        );

        let consensus = find_consensus_error(&node_errors);
        assert_eq!(consensus, Some(OprfNodeErrorCode::InvalidProof));
    }

    #[test]
    fn test_find_consensus_error_no_majority() {
        let mut node_errors = HashMap::new();
        node_errors.insert(
            "node1".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );
        node_errors.insert(
            "node2".to_string(),
            taceo_oprf::client::Error::ServerError("invalid merkle root".to_string()),
        );
        node_errors.insert(
            "node3".to_string(),
            taceo_oprf::client::Error::ServerError("unknown schema issuer: 1".to_string()),
        );

        let consensus = find_consensus_error(&node_errors);
        assert_eq!(consensus, None);
    }

    #[test]
    fn test_find_consensus_error_ignores_non_server_errors() {
        let mut node_errors = HashMap::new();
        node_errors.insert(
            "node1".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );
        node_errors.insert(
            "node2".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );
        node_errors.insert("node3".to_string(), taceo_oprf::client::Error::Eof);
        node_errors.insert(
            "node4".to_string(),
            taceo_oprf::client::Error::InvalidDLogProof,
        );

        // Only the 2 ServerError nodes count toward consensus
        // 2 out of 2 ServerErrors is > 50%, so consensus is found
        let consensus = find_consensus_error(&node_errors);
        assert_eq!(consensus, Some(OprfNodeErrorCode::InvalidProof));
    }

    #[test]
    fn test_find_consensus_error_no_server_errors() {
        let mut node_errors = HashMap::new();
        node_errors.insert("node1".to_string(), taceo_oprf::client::Error::Eof);
        node_errors.insert(
            "node2".to_string(),
            taceo_oprf::client::Error::InvalidDLogProof,
        );

        let consensus = find_consensus_error(&node_errors);
        assert_eq!(consensus, None);
    }

    #[test]
    fn test_convert_not_enough_responses_with_consensus() {
        let mut node_errors = HashMap::new();
        node_errors.insert(
            "node1".to_string(),
            taceo_oprf::client::Error::ServerError("unknown schema issuer: 127".to_string()),
        );
        node_errors.insert(
            "node2".to_string(),
            taceo_oprf::client::Error::ServerError("unknown schema issuer: 127".to_string()),
        );
        node_errors.insert(
            "node3".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );

        let err = taceo_oprf::client::Error::NotEnoughOprfResponses(3, node_errors);
        let proof_err = ProofError::from(err);

        match proof_err {
            ProofError::OprfNodeError {
                code,
                threshold_required,
                node_errors,
            } => {
                assert_eq!(code, OprfNodeErrorCode::UnknownSchemaIssuer);
                assert_eq!(threshold_required, 3);
                assert_eq!(node_errors.len(), 3);

                // Per-node errors are still preserved
                let by_url: HashMap<&str, &str> = node_errors
                    .iter()
                    .map(|(u, e)| (u.as_str(), e.as_str()))
                    .collect();
                assert!(
                    by_url
                        .get("node1")
                        .unwrap()
                        .contains("unknown schema issuer")
                );
                assert!(
                    by_url
                        .get("node2")
                        .unwrap()
                        .contains("unknown schema issuer")
                );
                assert!(by_url.get("node3").unwrap().contains("invalid proof"));
            }
            _ => panic!("Expected OprfNodeError, got {proof_err:?}"),
        }
    }

    #[test]
    fn test_convert_not_enough_responses_no_consensus() {
        // All different server errors — no majority
        let mut node_errors = HashMap::new();
        node_errors.insert(
            "node1".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );
        node_errors.insert(
            "node2".to_string(),
            taceo_oprf::client::Error::ServerError("invalid merkle root".to_string()),
        );
        node_errors.insert(
            "node3".to_string(),
            taceo_oprf::client::Error::ServerError("invalid signer".to_string()),
        );

        let err = taceo_oprf::client::Error::NotEnoughOprfResponses(3, node_errors);
        let proof_err = ProofError::from(err);

        match &proof_err {
            ProofError::OprfNodeError {
                code,
                threshold_required,
                node_errors,
            } => {
                assert!(
                    matches!(code, OprfNodeErrorCode::Unknown(_)),
                    "Expected Unknown code when no consensus, got {code:?}"
                );
                assert_eq!(*threshold_required, 3);
                assert_eq!(node_errors.len(), 3);
            }
            _ => panic!("Expected OprfNodeError, got {proof_err:?}"),
        }
    }

    #[test]
    fn test_convert_not_enough_responses_empty_errors() {
        let node_errors = HashMap::new();
        let err = taceo_oprf::client::Error::NotEnoughOprfResponses(3, node_errors);
        let proof_err = ProofError::from(err);

        match &proof_err {
            ProofError::OprfNodeError {
                code,
                threshold_required,
                node_errors,
            } => {
                match code {
                    OprfNodeErrorCode::Unknown(_) => {}
                    _ => panic!("Expected Unknown code for empty errors"),
                }
                assert_eq!(*threshold_required, 3);
                assert!(node_errors.is_empty());
                // Display should indicate no details
                let msg = format!("{proof_err}");
                assert!(msg.contains("no error details"));
            }
            _ => panic!("Expected OprfNodeError"),
        }
    }

    #[test]
    fn test_convert_other_oprf_errors_pass_through() {
        let err = taceo_oprf::client::Error::InvalidDLogProof;
        let proof_err = ProofError::from(err);
        assert!(matches!(proof_err, ProofError::OprfError(_)));

        let err = taceo_oprf::client::Error::InconsistentOprfPublicKeys;
        let proof_err = ProofError::from(err);
        assert!(matches!(proof_err, ProofError::OprfError(_)));
    }

    #[test]
    fn test_display_includes_consensus_code_and_node_errors() {
        let mut node_errors = HashMap::new();
        node_errors.insert(
            "node1".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );
        node_errors.insert(
            "node2".to_string(),
            taceo_oprf::client::Error::ServerError("invalid proof".to_string()),
        );

        let err = taceo_oprf::client::Error::NotEnoughOprfResponses(2, node_errors);
        let proof_err = ProofError::from(err);
        let msg = format!("{proof_err}");

        assert!(msg.contains("threshold"));
        assert!(msg.contains("2 required"));
        assert!(msg.contains("consensus error"));
        assert!(msg.contains("invalid proof"));
        assert!(msg.contains("node1"));
        assert!(msg.contains("node2"));
    }
}
