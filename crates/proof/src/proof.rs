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

/// This module contains error types and validation functions for World ID proof inputs.
///
/// These are intended to assist in producing more helpul error messages for a given proof.
/// If the circuits change in any way, these checks may also need to be updated to match the new logic.
pub mod errors {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Zero;
    use eddsa_babyjubjub::EdDSAPublicKey;
    use taceo_oprf::core::{dlog_equality::DLogEqualityProof, oprf::BlindingFactor};
    use world_id_primitives::{
        FieldElement,
        authenticator::{AuthenticatorPublicKeySet, MAX_AUTHENTICATOR_KEYS},
        circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput},
        merkle::MerkleInclusionProof,
    };

    type BaseField = ark_babyjubjub::Fq;
    type Affine = ark_babyjubjub::EdwardsAffine;

    #[derive(Debug, thiserror::Error)]
    /// Errors that can occur when validating the inputs for a single World ID proof.
    pub enum ProofInputError {
        /// The specified Merkle tree depth is invalid.
        #[error("The specified Merkle tree depth is invalid (expected: {expected}, got: {is}).")]
        InvalidMerkleTreeDepth {
            /// Expected depth.
            expected: usize,
            /// Actual depth.
            is: BaseField,
        },
        /// The set of authenticator public keys is invalid.
        #[error("The set of authenticator public keys is invalid.")]
        InvalidAuthenticatorPublicKeySet,
        /// The provided Merkle tree inclusion proof is invalid.
        #[error("The provided Merkle tree inclusion proof is invalid.")]
        InvalidMerkleTreeInclusionProof,
        /// The signature over the nonce and RP ID is invalid.
        #[error("The signature over the nonce and RP ID is invalid.")]
        InvalidQuerySignature,
        /// The provided blinding factor is invalid.
        #[error("The provided blinding factor is invalid.")]
        InvalidBlindingFactor,
        /// The provided credential has expired.
        #[error(
            "The provided credential has expired (expires_at: {expires_at}, check_timestamp: {current_timestamp})."
        )]
        CredentialExpired {
            /// Current timestamp.
            current_timestamp: u64,
            /// Expiration timestamp.
            expires_at: u64,
        },
        /// The provided credential genesis issue timestamp is expired.
        #[error(
            "The provided credential has a genesis issued at date that is too old (genesis_issued_at: {genesis_issued_at}, check_timestamp: {genesis_issued_at_min})."
        )]
        CredentialGenesisExpired {
            /// Minimum Issue date.
            genesis_issued_at_min: u64,
            /// Genesis issue timestamp.
            genesis_issued_at: u64,
        },
        /// A value is out of bounds.
        #[error("The value '{name}' is out of bounds (got: {is}, limit: {limit}).")]
        ValueOutOfBounds {
            /// Name of the value for error message.
            name: &'static str,
            /// Actual value.
            is: BaseField,
            /// Upper limit, not inclusive.
            limit: BaseField,
        },
        /// The credential signature is invalid.
        #[error("The credential signature is invalid for the given credential public key.")]
        InvalidCredentialSignature,
        /// The provided point is not a valid point in the prime-order subgroup of the `BabyJubJub` curve.
        #[error(
            "The provided point '{name}' is not a valid point in the prime-order subgroup of the BabyJubJub curve."
        )]
        InvalidBabyJubJubPoint {
            /// Name of the point for error message.
            name: &'static str,
        },
        /// The provided OPRF proof is invalid.
        #[error("The provided OPRF DlogEquality proof is invalid.")]
        InvalidOprfProof,
        /// The provided unblinded OPRF response point is invalid.
        #[error("The provided unblinded OPRF response point is invalid.")]
        InvalidOprfResponse,
        /// The provided session ID commitment is invalid.
        #[error(
            "The provided session ID commitment is invalid for the given id and session id randomness."
        )]
        InvalidIdCommitment,
    }

    /// This method checks the validity of the input parameters by emulating the operations that are proved in ZK and raising Errors that would result in an invalid proof.
    ///
    /// Returns the blinded OPRF query point if everything is ok.
    ///
    /// # Errors
    /// This function will return a [`ProofInputError`] if any of the checks fail.
    /// The `Display` implementation of this error can be used to get a human-readable error message on which parts of the input were invalid.
    pub fn check_query_input_validity<const TREE_DEPTH: usize>(
        inputs: &QueryProofCircuitInput<TREE_DEPTH>,
    ) -> Result<Affine, ProofInputError> {
        // 1. Check that the depth is within bounds.
        if inputs.depth != BaseField::new((TREE_DEPTH as u64).into()) {
            return Err(ProofInputError::InvalidMerkleTreeDepth {
                expected: TREE_DEPTH,
                is: inputs.depth,
            });
        }
        // 2. Check the merkle proof is valid
        // Check the Merkle tree idx is valid.
        let idx_u64 = u64::try_from(FieldElement::from(inputs.mt_index)).map_err(|_| {
            ProofInputError::ValueOutOfBounds {
                name: "Merkle tree index",
                is: inputs.mt_index,
                limit: BaseField::new((1u64 << TREE_DEPTH).into()),
            }
        })?;
        if idx_u64 >= (1u64 << TREE_DEPTH) {
            return Err(ProofInputError::ValueOutOfBounds {
                name: "Merkle tree index",
                is: inputs.mt_index,
                limit: BaseField::new((1u64 << TREE_DEPTH).into()),
            });
        }

        // Build the leaf from the PKs.
        let pk_set = AuthenticatorPublicKeySet::new(Some(
            inputs
                .pk
                .iter()
                .map(|&x| EdDSAPublicKey { pk: x })
                .collect(),
        ))
        .map_err(|_| ProofInputError::InvalidAuthenticatorPublicKeySet)?;
        let pk_set_hash = pk_set.leaf_hash();
        let merkle_tree_inclusion_proof = MerkleInclusionProof::new(
            FieldElement::from(inputs.merkle_root),
            idx_u64,
            inputs.siblings.map(FieldElement::from),
        );
        if !merkle_tree_inclusion_proof.is_valid(FieldElement::from(pk_set_hash)) {
            return Err(ProofInputError::InvalidMerkleTreeInclusionProof);
        }

        // 3. Check that the signature is valid.
        let pk_index_usize =
            usize::try_from(FieldElement::from(inputs.pk_index)).map_err(|_| {
                ProofInputError::ValueOutOfBounds {
                    name: "Authenticator PubKey index",
                    is: inputs.pk_index,
                    limit: BaseField::new((MAX_AUTHENTICATOR_KEYS as u64).into()),
                }
            })?;
        let pk = pk_set
            .get(pk_index_usize)
            .ok_or_else(|| ProofInputError::ValueOutOfBounds {
                name: "Authenticator PubKey index",
                is: inputs.pk_index,
                limit: BaseField::new((MAX_AUTHENTICATOR_KEYS as u64).into()),
            })?;

        if !inputs.r.is_on_curve() || !inputs.r.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ProofInputError::InvalidBabyJubJubPoint {
                name: "Query Signature R",
            });
        }
        if !pk.pk.is_on_curve() || !pk.pk.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ProofInputError::InvalidBabyJubJubPoint {
                name: "Authenticator Public Key",
            });
        }

        let _rp_id_u64 = u64::try_from(FieldElement::from(inputs.rp_id)).map_err(|_| {
            ProofInputError::ValueOutOfBounds {
                name: "RP Id",
                is: inputs.pk_index,
                limit: BaseField::new((MAX_AUTHENTICATOR_KEYS as u64).into()),
            }
        })?;
        let query = world_id_primitives::authenticator::oprf_query_digest(
            idx_u64,
            FieldElement::from(inputs.action),
            FieldElement::from(inputs.rp_id),
        );
        let signature = eddsa_babyjubjub::EdDSASignature {
            r: inputs.r,
            s: inputs.s,
        };

        if !pk.verify(*query, &signature) {
            return Err(ProofInputError::InvalidQuerySignature);
        }

        let blinding_factor = BlindingFactor::from_scalar(inputs.beta)
            .map_err(|_| ProofInputError::InvalidBlindingFactor)?;
        let query_point = taceo_oprf::core::oprf::client::blind_query(*query, blinding_factor);

        Ok(query_point.blinded_query())
    }

    /// This method checks the validity of the input parameters by emulating the operations that are proved in ZK and raising Errors that would result in an invalid proof.
    ///
    /// Returns the computed nullifier if everything is ok.
    ///
    /// # Errors
    /// This function will return a [`ProofInputError`] if any of the checks fail.
    /// The `Display` implementation of this error can be used to get a human-readable error message on which parts of the input were invalid.
    #[expect(
        clippy::too_many_lines,
        reason = "necessary checks for input validity should be in one function"
    )]
    pub fn check_nullifier_input_validity<const TREE_DEPTH: usize>(
        inputs: &NullifierProofCircuitInput<TREE_DEPTH>,
    ) -> Result<FieldElement, ProofInputError> {
        // 1. Check the validity of the query input.
        let blinded_query = check_query_input_validity(&inputs.query_input)?;

        // 2. Credential validity checks
        // Check timestamps are within bounds.
        let current_timestamp_u64 = u64::try_from(FieldElement::from(inputs.current_timestamp))
            .map_err(|_| ProofInputError::ValueOutOfBounds {
                name: "current timestamp",
                is: inputs.current_timestamp,
                limit: BaseField::new(u64::MAX.into()),
            })?;
        let credential_expires_at_u64 = u64::try_from(FieldElement::from(inputs.cred_expires_at))
            .map_err(|_| ProofInputError::ValueOutOfBounds {
            name: "credential expiry timestamp",
            is: inputs.current_timestamp,
            limit: BaseField::new(u64::MAX.into()),
        })?;
        // Check that the credential has not expired.
        if credential_expires_at_u64 <= current_timestamp_u64 {
            return Err(ProofInputError::CredentialExpired {
                current_timestamp: current_timestamp_u64,
                expires_at: credential_expires_at_u64,
            });
        }
        // Genesis checks
        let genesis_issued_at_u64 =
            u64::try_from(FieldElement::from(inputs.cred_genesis_issued_at)).map_err(|_| {
                ProofInputError::ValueOutOfBounds {
                    name: "credential genesis issued at",
                    is: inputs.cred_genesis_issued_at,
                    limit: BaseField::new(u64::MAX.into()),
                }
            })?;
        let genesis_issued_at_min_u64 =
            u64::try_from(FieldElement::from(inputs.cred_genesis_issued_at_min)).map_err(|_| {
                ProofInputError::ValueOutOfBounds {
                    name: "credential genesis issued at minimum bound",
                    is: inputs.cred_genesis_issued_at_min,
                    limit: BaseField::new(u64::MAX.into()),
                }
            })?;
        if genesis_issued_at_min_u64 > genesis_issued_at_u64 {
            return Err(ProofInputError::CredentialGenesisExpired {
                genesis_issued_at_min: genesis_issued_at_min_u64,
                genesis_issued_at: genesis_issued_at_u64,
            });
        }

        let blinded_subject = sub(
            FieldElement::from(inputs.query_input.mt_index),
            FieldElement::from(inputs.cred_sub_blinding_factor),
        );

        let cred_hash = hash_credential(
            FieldElement::from(inputs.issuer_schema_id),
            blinded_subject,
            FieldElement::from(inputs.cred_genesis_issued_at),
            FieldElement::from(inputs.cred_expires_at),
            FieldElement::from(inputs.cred_hashes[0]),
            FieldElement::from(inputs.cred_hashes[1]),
            FieldElement::from(inputs.cred_id),
        );
        let pk = EdDSAPublicKey { pk: inputs.cred_pk };

        let signature = eddsa_babyjubjub::EdDSASignature {
            r: inputs.cred_r,
            s: inputs.cred_s,
        };

        if !inputs.cred_r.is_on_curve() || !inputs.cred_r.is_in_correct_subgroup_assuming_on_curve()
        {
            return Err(ProofInputError::InvalidBabyJubJubPoint {
                name: "Credential Signature R",
            });
        }
        if !pk.pk.is_on_curve() || !pk.pk.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ProofInputError::InvalidBabyJubJubPoint {
                name: "Credential Public Key",
            });
        }

        if !pk.verify(*cred_hash, &signature) {
            return Err(ProofInputError::InvalidCredentialSignature);
        }

        // 3. Dlog Equality proof checks
        if !inputs.oprf_pk.is_on_curve()
            || !inputs.oprf_pk.is_in_correct_subgroup_assuming_on_curve()
        {
            return Err(ProofInputError::InvalidBabyJubJubPoint {
                name: "OPRF Public Key",
            });
        }
        if !inputs.oprf_response_blinded.is_on_curve()
            || !inputs
                .oprf_response_blinded
                .is_in_correct_subgroup_assuming_on_curve()
        {
            return Err(ProofInputError::InvalidBabyJubJubPoint {
                name: "OPRF Blinded Response",
            });
        }

        // check dlog eq proof is valid
        let dlog_proof = DLogEqualityProof {
            e: inputs.dlog_e,
            s: inputs.dlog_s,
        };
        dlog_proof
            .verify(
                inputs.oprf_pk,
                blinded_query,
                inputs.oprf_response_blinded,
                Affine::generator(),
            )
            .map_err(|_| ProofInputError::InvalidOprfProof)?;

        // check that the unblinded response is correct
        if !inputs.oprf_response.is_on_curve()
            || !inputs
                .oprf_response
                .is_in_correct_subgroup_assuming_on_curve()
        {
            return Err(ProofInputError::InvalidBabyJubJubPoint {
                name: "OPRF Unblinded Response",
            });
        }
        let expected_blinded_response =
            (inputs.oprf_response * inputs.query_input.beta).into_affine();
        if expected_blinded_response != inputs.oprf_response_blinded {
            return Err(ProofInputError::InvalidOprfResponse);
        }

        // check that session_id commitment is correct
        if !inputs.id_commitment.is_zero() {
            let expected_commitment = session_id_commitment(
                FieldElement::from(inputs.query_input.mt_index),
                FieldElement::from(inputs.id_commitment_r),
            );
            if expected_commitment != FieldElement::from(inputs.id_commitment) {
                return Err(ProofInputError::InvalidIdCommitment);
            }
        }

        // 4. Compute the nullifier
        let nullfier = oprf_finalize_hash(
            *world_id_primitives::authenticator::oprf_query_digest(
                #[expect(
                    clippy::missing_panics_doc,
                    reason = "checked in check_query_input_validity"
                )]
                u64::try_from(FieldElement::from(inputs.query_input.mt_index)).unwrap(),
                FieldElement::from(inputs.query_input.action),
                FieldElement::from(inputs.query_input.rp_id),
            ),
            inputs.oprf_response,
        );

        Ok(nullfier)
    }

    // Helper functions to recompute various hashes used in the circuit

    // Recompute the blinded subject, copied from credential
    fn sub(leaf_index: FieldElement, blinding_factor: FieldElement) -> FieldElement {
        let sub_ds = FieldElement::from_be_bytes_mod_order(b"H_CS(id, r)");
        let mut input = [*sub_ds, *leaf_index, *blinding_factor];
        poseidon2::bn254::t3::permutation_in_place(&mut input);
        input[1].into()
    }
    // Recompute the OPRF finalization hash
    fn oprf_finalize_hash(query: BaseField, oprf_response: Affine) -> FieldElement {
        let finalize_ds = FieldElement::from_be_bytes_mod_order(super::OPRF_PROOF_DS);
        let mut input = [*finalize_ds, query, oprf_response.x, oprf_response.y];
        poseidon2::bn254::t4::permutation_in_place(&mut input);
        input[1].into()
    }

    // Recompute the session_id_commitment
    fn session_id_commitment(user_id: FieldElement, commitment_rand: FieldElement) -> FieldElement {
        let sub_ds = FieldElement::from_be_bytes_mod_order(b"H(id, r)");
        let mut input = [*sub_ds, *user_id, *commitment_rand];
        poseidon2::bn254::t3::permutation_in_place(&mut input);
        input[1].into()
    }

    // Recompute the credential hash, copied from credential
    fn hash_credential(
        issuer_schema_id: FieldElement,
        sub: FieldElement,
        genesis_issued_at: FieldElement,
        expires_at: FieldElement,
        claims_hash: FieldElement,
        associated_data_hash: FieldElement,
        id: FieldElement,
    ) -> FieldElement {
        let cred_ds = FieldElement::from_be_bytes_mod_order(b"POSEIDON2+EDDSA-BJJ");
        let mut input = [
            *cred_ds,
            *issuer_schema_id,
            *sub,
            *genesis_issued_at,
            *expires_at,
            *claims_hash,
            *associated_data_hash,
            *id,
        ];
        poseidon2::bn254::t8::permutation_in_place(&mut input);
        input[1].into()
    }
}
