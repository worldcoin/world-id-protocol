//! Internal proof generation for the World ID Protocol.
//!
//! Provides functionality for generating Uniqueness Proofs (internally also called
//! Nullifier Proofs `π2`) and Session Proofs.
//!
//! The proof generation workflow for Uniqueness Proofs consists of:
//! 1. Loading circuit proving material (zkeys and witness graphs)
//! 2. Signing OPRF queries and generating a Query Proof `π1` (see [`crate::oprf_query`])
//! 3. Interacting with OPRF services to obtain challenge responses
//! 4. Verifying `DLog` equality proofs from OPRF nodes
//! 5. Generating the final Uniqueness Proof `π2`

use crate::ProofError;
use ark_bn254::Bn254;
use ark_ff::BigInt;
use rand::{CryptoRng, Rng};
use std::{io::Read, path::Path};
use world_id_primitives::{Credential, FieldElement, Nullifier, RequestItem, TREE_DEPTH};

use crate::circuit_inputs::NullifierProofCircuitInput;

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

#[expect(unused_imports, reason = "used for docs")]
use world_id_primitives::SessionId;

use crate::oprf_query::FullOprfOutput;

pub mod errors;

pub(crate) const OPRF_PROOF_DS: &[u8] = b"World ID Proof";

/// The SHA-256 fingerprint of the `OPRFNullifier` `ZKey`.
pub const NULLIFIER_ZKEY_FINGERPRINT: &str =
    "4247e6bfe1af211e72d3657346802e1af00e6071fb32429a200f9fc0a25a36f9";

/// The SHA-256 fingerprint of the `OPRFNullifier` witness graph.
pub const NULLIFIER_GRAPH_FINGERPRINT: &str =
    "c1d951716e3b74b72e4ea0429986849cadc43cccc630a7ee44a56a6199a66b9a";

// ============================================================================
// Circuit Material Loaders
// ============================================================================

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

/// Loads the [`CircomGroth16Material`] for the nullifier proof from the provided paths.
///
/// # Errors
/// Will return an error if the material cannot be loaded or verified.
pub fn load_nullifier_material_from_paths(
    zkey: impl AsRef<Path>,
    graph: impl AsRef<Path>,
) -> eyre::Result<CircomGroth16Material> {
    Ok(build_nullifier_builder().build_from_paths(zkey, graph)?)
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
    oprf_output: FullOprfOutput,
    request_item: &RequestItem,
    session_id: Option<FieldElement>,
    session_id_r_seed: Option<FieldElement>,
    expires_at_min: u64,
) -> Result<
    (
        ark_groth16::Proof<Bn254>,
        Vec<ark_babyjubjub::Fq>,
        Nullifier,
    ),
    ProofError,
> {
    let cred_signature = credential
        .signature
        .clone()
        .ok_or_else(|| ProofError::InternalError(eyre::eyre!("Credential not signed")))?;

    let nullifier_from_oprf_output = oprf_output.verifiable_oprf_output.output;

    let nullifier_input = NullifierProofCircuitInput::<TREE_DEPTH> {
        query_input: oprf_output.query_proof_input,
        issuer_schema_id: credential.issuer_schema_id.into(),
        cred_pk: credential.issuer.pk,
        cred_hashes: [
            *credential.claims_hash()?,
            *credential.associated_data_commitment,
        ],
        cred_genesis_issued_at: credential.genesis_issued_at.into(),
        cred_genesis_issued_at_min: request_item.genesis_issued_at_min.unwrap_or(0).into(),
        cred_expires_at: credential.expires_at.into(),
        cred_id: BigInt([credential.id, u64::from(credential.issuer_version), 0, 0]).into(),
        cred_sub_blinding_factor: *credential_sub_blinding_factor,
        cred_s: cred_signature.s,
        cred_r: cred_signature.r,
        id_commitment_r: *session_id_r_seed.unwrap_or(FieldElement::ZERO),
        id_commitment: *session_id.unwrap_or(FieldElement::ZERO),
        dlog_e: oprf_output.verifiable_oprf_output.dlog_proof.e(),
        dlog_s: oprf_output.verifiable_oprf_output.dlog_proof.s(),
        oprf_pk: oprf_output.verifiable_oprf_output.oprf_public_key.inner(),
        oprf_response_blinded: oprf_output.verifiable_oprf_output.blinded_response,
        oprf_response: oprf_output.verifiable_oprf_output.unblinded_response,
        signal_hash: *request_item.signal_hash(),
        // The `current_timestamp` constraint in the circuit is used to specify the minimum expiration time for the credential.
        // The circuit verifies that `current_timestamp < cred_expires_at`.
        current_timestamp: expires_at_min.into(),
    };

    let _ = errors::check_nullifier_input_validity(&nullifier_input)?;

    let (proof, public) = nullifier_material.generate_proof(&nullifier_input, rng)?;
    nullifier_material.verify_proof(&proof, &public)?;

    // Verify that the computed nullifier matches the OPRF output.
    if public[0] != nullifier_from_oprf_output {
        return Err(ProofError::InternalError(eyre::eyre!(
            "Computed nullifier does not match OPRF output"
        )));
    }

    let nullifier: Nullifier = FieldElement::from(public[0]).into();

    Ok((proof, public, nullifier))
}
