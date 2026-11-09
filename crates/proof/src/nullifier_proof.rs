//! Internal proof generation for the World ID Protocol.
//!
//! Provides functionality for generating Uniqueness Proofs (internally also called
//! Nullifier Proofs `π2`) and Session Proofs.
//!
//! The proof generation workflow for Uniqueness Proofs consists of:
//! 1. Loading circuit proving material (zkeys and witness graphs)
//! 2. Signing OPRF queries and generating a Query Proof `π1` (see `crate::oprf_query_proof`)
//! 3. Interacting with OPRF services to obtain challenge responses
//! 4. Verifying `DLog` equality proofs from OPRF nodes
//! 5. Generating the final Uniqueness Proof `π2`

use crate::{
    ProofError, ProofInputError, groth16::groth16_material_builder,
    oprf_query_proof::check_query_input_validity,
};
use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, Zero};
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng};
use std::{io::Read, path::Path};
use taceo_oprf::core::dlog_equality::DLogEqualityProof;
use world_id_primitives::{
    Credential, FieldElement, Nullifier, RequestItem, TREE_DEPTH,
    poseidon::{self, ds},
};

type BaseField = ark_babyjubjub::Fq;
type Affine = ark_babyjubjub::EdwardsAffine;

use crate::circuit_inputs::NullifierProofCircuitInput;

pub use groth16_material::circom::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, ZkeyError,
};

#[expect(unused_imports, reason = "used for docs")]
use world_id_primitives::SessionId;

use crate::oprf_query_proof::FullOprfOutput;

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
    groth16_material_builder(NULLIFIER_ZKEY_FINGERPRINT, NULLIFIER_GRAPH_FINGERPRINT)
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
            *credential
                .claims_hash()
                .map_err(ProofError::CredentialError)?,
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

    let _ = check_nullifier_input_validity(&nullifier_input)?;

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

// ============================================================================
// Input Check
// ============================================================================

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
            is: inputs.cred_expires_at,
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
    let genesis_issued_at_u64 = u64::try_from(FieldElement::from(inputs.cred_genesis_issued_at))
        .map_err(|_| ProofInputError::ValueOutOfBounds {
            name: "credential genesis issued at",
            is: inputs.cred_genesis_issued_at,
            limit: BaseField::new(u64::MAX.into()),
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

    if !inputs.cred_r.is_on_curve() || !inputs.cred_r.is_in_correct_subgroup_assuming_on_curve() {
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
    if !inputs.oprf_pk.is_on_curve() || !inputs.oprf_pk.is_in_correct_subgroup_assuming_on_curve() {
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
    let dlog_proof = DLogEqualityProof::new(inputs.dlog_e, inputs.dlog_s);
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
    let expected_blinded_response = (inputs.oprf_response * inputs.query_input.beta).into_affine();
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
            return Err(ProofInputError::InvalidSessionId);
        }
    }

    // 4. Compute the nullifier
    let nullifier = oprf_finalize_hash(
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

    Ok(nullifier)
}

// Helper functions to recompute various hashes used in the circuit

// Recompute the blinded subject, copied from credential
fn sub(leaf_index: FieldElement, blinding_factor: FieldElement) -> FieldElement {
    poseidon::hash(ds::CREDENTIAL_SUB, [leaf_index, blinding_factor])
}
// Recompute the OPRF finalization hash
fn oprf_finalize_hash(query: BaseField, oprf_response: Affine) -> FieldElement {
    poseidon::hash(
        ds::OPRF_PROOF,
        [query.into(), oprf_response.x.into(), oprf_response.y.into()],
    )
}

// Recompute the session_id_commitment
fn session_id_commitment(user_id: FieldElement, commitment_rand: FieldElement) -> FieldElement {
    poseidon::hash(ds::SESSION_COMMITMENT, [user_id, commitment_rand])
}

// Recompute the credential hash, copied from credential
fn hash_credential(
    issuer_schema_id: FieldElement,
    sub: FieldElement,
    genesis_issued_at: FieldElement,
    expires_at: FieldElement,
    claims_hash: FieldElement,
    associated_data_commitment: FieldElement,
    id: FieldElement,
) -> FieldElement {
    poseidon::hash(
        ds::CREDENTIAL_V1,
        [
            issuer_schema_id,
            sub,
            genesis_issued_at,
            expires_at,
            claims_hash,
            associated_data_commitment,
            id,
        ],
    )
}

#[cfg(test)]
mod input_validation_tests {
    use std::str::FromStr;

    use ark_ec::twisted_edwards::Affine;

    use super::check_nullifier_input_validity;
    use crate::{
        circuit_inputs::NullifierProofCircuitInput,
        oprf_query_proof::input_validation_tests::get_valid_query_proof_input,
    };

    fn get_valid_nullifier_proof_input() -> NullifierProofCircuitInput<30> {
        NullifierProofCircuitInput {
            query_input: get_valid_query_proof_input(),
            issuer_schema_id: ark_bn254::Fr::from(1u64),
            cred_pk: Affine {
                x: ark_babyjubjub::Fq::from_str(
                    "15406775215557320288232407896017344573719706795510112309920214099347968981892",
                )
                .unwrap(),
                y: ark_babyjubjub::Fq::from_str(
                    "486388649729314270871358770861421181497883381447163109744630700259216042819",
                )
                .unwrap(),
            },
            cred_hashes: [
                ark_bn254::Fr::from_str(
                    "14272087287699568472569351444185311392108883722570788958733484799744115401870",
                )
                .unwrap(),
                ark_bn254::Fr::from_str("0").unwrap(),
            ],
            cred_genesis_issued_at: ark_bn254::Fr::from(1770125923u64),
            cred_expires_at: ark_bn254::Fr::from(1770125983u64),
            cred_s: ark_babyjubjub::Fr::from_str(
                "1213918488111680600555111454085490191981091366153388773926786471247948539005",
            )
            .unwrap(),
            cred_r: Affine {
                x: ark_babyjubjub::Fq::from_str(
                    "15844586803954862856390946258558419582000810449135704981677693963391564067969",
                )
                .unwrap(),
                y: ark_babyjubjub::Fq::from_str(
                    "592710378120172403096018676235519447487818389124797234601458948988041235710",
                )
                .unwrap(),
            },
            current_timestamp: ark_bn254::Fr::from(1770125908u64),
            cred_genesis_issued_at_min: ark_bn254::Fr::from(0u64),
            cred_sub_blinding_factor: ark_bn254::Fr::from_str(
                "12170146734368267085913078854954627576787934009906407554611507307540342380837",
            )
            .unwrap(),
            cred_id: ark_bn254::Fr::from(3198767490419873482u64),
            id_commitment_r: ark_bn254::Fr::from_str(
                "11722352184830287916674945948108962396487445899741105828127518108056503126019",
            )
            .unwrap(),
            id_commitment: ark_bn254::Fr::from(0u64),
            dlog_e: ark_bn254::Fr::from_str(
                "20738873297635092620048980552264360096607713029337408079647701591795211132447",
            )
            .unwrap(),
            dlog_s: ark_babyjubjub::Fr::from_str(
                "409914485496464180245985942628922659137136006706846380135829705769429965654",
            )
            .unwrap(),
            oprf_pk: Affine {
                x: ark_babyjubjub::Fq::from_str(
                    "2124016492737602714904869498047199181102594928943726277329982080254326092458",
                )
                .unwrap(),
                y: ark_babyjubjub::Fq::from_str(
                    "13296886400185574560491768605341786437896334271868835545571935419923854148448",
                )
                .unwrap(),
            },
            oprf_response_blinded: Affine {
                x: ark_babyjubjub::Fq::from_str(
                    "186021305824089989598292966483056363224488147240980559441958002546059602483",
                )
                .unwrap(),
                y: ark_babyjubjub::Fq::from_str(
                    "16813058203546508924422863380215026034284821141284206571184467783067057954778",
                )
                .unwrap(),
            },
            oprf_response: Affine {
                x: ark_babyjubjub::Fq::from_str(
                    "10209445202057032226639052993170591937356545068582397532992536070677055126187",
                )
                .unwrap(),
                y: ark_babyjubjub::Fq::from_str(
                    "21877375411477040679486668720099554257785799784699842830375906922948306109699",
                )
                .unwrap(),
            },
            signal_hash: ark_bn254::Fr::from_str(
                "37938388892362834151584770384290207919364301626797345218722464515205243407",
            )
            .unwrap(),
        }
    }

    #[test]
    fn test_valid_nullifier_proof_input() {
        let inputs = get_valid_nullifier_proof_input();
        let _ = check_nullifier_input_validity(&inputs).unwrap();
    }

    #[test]
    fn test_invalid_nullifier_proof_input() {
        let inputs = get_valid_nullifier_proof_input();
        {
            let mut inputs = inputs.clone();
            inputs.current_timestamp =
                ark_babyjubjub::Fq::from_str("123465723894591324701234982134000070").unwrap(); // invalid timestamp
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::ValueOutOfBounds {
                    name: "current timestamp",
                    ..
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.current_timestamp = inputs.cred_expires_at;
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::CredentialExpired { .. }
            ));
        }
        {
            let mut inputs = inputs.clone();
            // genesis issued at 1770125923
            inputs.cred_genesis_issued_at_min = ark_bn254::Fr::from(1770125924u64);
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::CredentialGenesisExpired { .. }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.cred_r = Affine {
                x: ark_babyjubjub::Fq::from(1u64),
                y: ark_babyjubjub::Fq::from(2u64),
            };
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidBabyJubJubPoint {
                    name: "Credential Signature R"
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.cred_pk = Affine {
                x: ark_babyjubjub::Fq::from(1u64),
                y: ark_babyjubjub::Fq::from(2u64),
            };
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidBabyJubJubPoint {
                    name: "Credential Public Key"
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.cred_s = ark_babyjubjub::Fr::from(12345u64);
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidCredentialSignature
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.oprf_pk = Affine {
                x: ark_babyjubjub::Fq::from(1u64),
                y: ark_babyjubjub::Fq::from(2u64),
            };
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidBabyJubJubPoint {
                    name: "OPRF Public Key"
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.oprf_response_blinded = Affine {
                x: ark_babyjubjub::Fq::from(1u64),
                y: ark_babyjubjub::Fq::from(2u64),
            };
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidBabyJubJubPoint {
                    name: "OPRF Blinded Response"
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.dlog_s = ark_babyjubjub::Fr::from(12345u64);
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidOprfProof
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.oprf_response = Affine {
                x: ark_babyjubjub::Fq::from(1u64),
                y: ark_babyjubjub::Fq::from(2u64),
            };
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidBabyJubJubPoint {
                    name: "OPRF Unblinded Response"
                }
            ));
        }
        {
            let mut inputs = inputs.clone();
            // Valid point but incorrect for the blinded response
            use ark_ec::AffineRepr;
            inputs.oprf_response = ark_babyjubjub::EdwardsAffine::generator();
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidOprfResponse
            ));
        }
        {
            let mut inputs = inputs.clone();
            inputs.id_commitment = ark_bn254::Fr::from(12345u64);
            assert!(matches!(
                check_nullifier_input_validity(&inputs).unwrap_err(),
                crate::ProofInputError::InvalidSessionId
            ));
        }
    }

    /// Verifies that the `cred_id` slot of the credential hash, which packs the
    /// `Credential::id` and `Credential::issuer_version`, is computed
    /// consistently between `Credential::hash` and the validation path used by
    /// `check_nullifier_input_validity`.
    ///
    /// This protects against the proof-input validator silently diverging from
    /// the issuer's actual signed hash when `issuer_version` is non-zero.
    #[test]
    fn test_packed_cred_id_matches_credential_hash() {
        use super::hash_credential;
        use ark_ff::BigInt;
        use world_id_primitives::{Credential, FieldElement};

        let mut credential = Credential::new();
        credential.id = 0x1234_5678_9ABC_DEF0;
        credential.issuer_version = 7;
        credential.issuer_schema_id = 42;
        credential.sub = FieldElement::from(100u64);
        credential.genesis_issued_at = 1_000_000;
        credential.expires_at = 2_000_000;

        let direct = credential.hash().unwrap();

        let packed_cred_id: ark_babyjubjub::Fq =
            BigInt([credential.id, u64::from(credential.issuer_version), 0, 0]).into();

        let via_validation = hash_credential(
            FieldElement::from(credential.issuer_schema_id),
            credential.sub,
            FieldElement::from(credential.genesis_issued_at),
            FieldElement::from(credential.expires_at),
            credential.claims_hash().unwrap(),
            credential.associated_data_commitment,
            FieldElement::from(packed_cred_id),
        );

        assert_eq!(
            direct, via_validation,
            "packed cred_id must reproduce Credential::hash"
        );

        let unpacked_cred_id: ark_babyjubjub::Fq = credential.id.into();
        let via_validation_unpacked = hash_credential(
            FieldElement::from(credential.issuer_schema_id),
            credential.sub,
            FieldElement::from(credential.genesis_issued_at),
            FieldElement::from(credential.expires_at),
            credential.claims_hash().unwrap(),
            credential.associated_data_commitment,
            FieldElement::from(unpacked_cred_id),
        );

        assert_ne!(
            direct, via_validation_unpacked,
            "passing only id (without issuer_version) must NOT reproduce Credential::hash"
        );
    }
}
