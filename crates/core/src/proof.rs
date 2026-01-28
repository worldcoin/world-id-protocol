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
use std::{io::Read, path::Path};
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
        "rp", // module for World ID RP use-case
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
        expiration_timestamp: args.expiration_timestamp,
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

#[cfg(feature = "authenticator")]
/// This module contains error types and validation functions for World ID proof inputs.
///
/// These are intended to assist in producing more helpul error messages for a given proof.
/// If the circuits change in any way, these checks may also need to be updated to match the new logic.
pub mod errors {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Zero;
    use eddsa_babyjubjub::EdDSAPublicKey;
    use poseidon2::{POSEIDON2_BN254_T3_PARAMS, POSEIDON2_BN254_T4_PARAMS, Poseidon2};
    use taceo_oprf_core::dlog_equality::DLogEqualityProof;
    use world_id_primitives::{
        FieldElement,
        authenticator::{AuthenticatorPublicKeySet, MAX_AUTHENTICATOR_KEYS},
        circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput},
        merkle::MerkleInclusionProof,
        rp::RpId,
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

        let rp_id_u64 = u64::try_from(FieldElement::from(inputs.rp_id)).map_err(|_| {
            ProofInputError::ValueOutOfBounds {
                name: "RP Id",
                is: inputs.pk_index,
                limit: BaseField::new((MAX_AUTHENTICATOR_KEYS as u64).into()),
            }
        })?;
        let query = super::query_hash(
            idx_u64,
            RpId::from(rp_id_u64),
            FieldElement::from(inputs.action),
        );
        let signature = eddsa_babyjubjub::EdDSASignature {
            r: inputs.r,
            s: inputs.s,
        };

        if !pk.verify(query, &signature) {
            return Err(ProofInputError::InvalidQuerySignature);
        }

        if inputs.beta.is_zero() {
            return Err(ProofInputError::InvalidBlindingFactor);
        }
        // let query_point = taceo_oprf_core::oprf::client::blind_query(query, inputs.beta.into());
        // Ok(query_point.blinded_query())
        Ok(Affine::zero()) // Stub return value
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
            super::query_hash(
                #[expect(
                    clippy::missing_panics_doc,
                    reason = "checked in check_query_input_validity"
                )]
                u64::try_from(FieldElement::from(inputs.query_input.mt_index)).unwrap(),
                #[expect(
                    clippy::missing_panics_doc,
                    reason = "checked in check_query_input_validity"
                )]
                RpId::from(u64::try_from(FieldElement::from(inputs.query_input.rp_id)).unwrap()),
                FieldElement::from(inputs.query_input.action),
            ),
            inputs.oprf_response,
        );

        Ok(nullfier)
    }

    // Helper functions to recompute various hashes used in the circuit

    // Recompute the blinded subject, copied from credential
    fn sub(leaf_index: FieldElement, blinding_factor: FieldElement) -> FieldElement {
        let hasher = Poseidon2::new(&POSEIDON2_BN254_T3_PARAMS);
        let sub_ds = FieldElement::from_be_bytes_mod_order(b"H_CS(id, r)");
        let mut input = [*sub_ds, *leaf_index, *blinding_factor];
        hasher.permutation_in_place(&mut input);
        input[1].into()
    }
    // Recompute the OPRF finalization hash
    fn oprf_finalize_hash(query: BaseField, oprf_response: Affine) -> FieldElement {
        let hasher = Poseidon2::new(&POSEIDON2_BN254_T4_PARAMS);
        let finalize_ds = FieldElement::from_be_bytes_mod_order(super::OPRF_PROOF_DS);
        let mut input = [*finalize_ds, query, oprf_response.x, oprf_response.y];
        hasher.permutation_in_place(&mut input);
        input[1].into()
    }

    // Recompute the session_id_commitment
    fn session_id_commitment(user_id: FieldElement, commitment_rand: FieldElement) -> FieldElement {
        let hasher = Poseidon2::new(&POSEIDON2_BN254_T3_PARAMS);
        let sub_ds = FieldElement::from_be_bytes_mod_order(b"H(id, r)");
        let mut input = [*sub_ds, *user_id, *commitment_rand];
        hasher.permutation_in_place(&mut input);
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
        let hasher = Poseidon2::<_, 8, 5>::default();
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
        hasher.permutation_in_place(&mut input);
        input[1].into()
    }
}
