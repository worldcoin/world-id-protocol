//! Presentation-specific proofs over private issuer-attested credential claims.

use std::{collections::BTreeMap, io::Read, path::Path};

use ark_ff::{BigInt, BigInteger as _, PrimeField as _};
use eddsa_babyjubjub::EdDSAPublicKey;
use provekit_common::{InputMap, InputValue, NoirElement, NoirProof, PublicInputs};
use provekit_prover::Prove as _;
use provekit_verifier::Verify as _;
use world_id_primitives::{
    ClaimStatement, ClaimsProof, ClaimsProofRequest, Credential, FieldElement, ProofRequest,
    ResponseItem,
};

use crate::{
    ClaimsProver, ClaimsVerifier, NoirRepresentable as _, ProofError, artifacts::ZkArtifactSource,
    errors::ProofInputError,
};

/// Public values shared with the companion Circom nullifier proof.
#[derive(Debug, Clone)]
pub struct ClaimsProofContext {
    /// Issuer/schema identifier of the credential.
    pub issuer_schema_id: FieldElement,
    /// Issuer key that signed the credential.
    pub credential_public_key: EdDSAPublicKey,
    /// Timestamp input used by the nullifier proof's credential expiry policy.
    pub current_timestamp: FieldElement,
    /// Minimum accepted credential genesis timestamp.
    pub cred_genesis_issued_at_min: FieldElement,
    /// Nullifier output shared by both proofs.
    pub nullifier: FieldElement,
    /// Registered relying-party identifier.
    pub rp_id: FieldElement,
    /// Nullifier action shared by both proofs.
    pub action: FieldElement,
}

/// Private witness and public request data needed to generate a claims proof.
pub struct ClaimsProofInput<'a> {
    /// Signed credential whose claims are proven.
    pub credential: &'a Credential,
    /// Blinder used in the credential subject commitment.
    pub credential_sub_blinding_factor: FieldElement,
    /// Holder's private World ID leaf index.
    pub leaf_index: u64,
    /// Unblinded OPRF response shared with the nullifier proof.
    pub oprf_response: ark_babyjubjub::EdwardsAffine,
    /// Public values shared with the nullifier proof.
    pub context: ClaimsProofContext,
    /// RP-requested claims predicates.
    pub request: &'a ClaimsProofRequest,
}

/// Loads a claims proof prover from a reader containing PKP bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the prover cannot be deserialized.
pub fn load_claims_prover_from_reader(mut reader: impl Read) -> eyre::Result<ClaimsProver> {
    provekit_common::register_ntt();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads a claims proof prover from a PKP file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the prover cannot be deserialized.
pub fn load_claims_prover_from_path(path: impl AsRef<Path>) -> eyre::Result<ClaimsProver> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads a claims proof verifier from a reader containing PKV bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the verifier cannot be deserialized.
pub fn load_claims_verifier_from_reader(mut reader: impl Read) -> eyre::Result<ClaimsVerifier> {
    provekit_common::register_ntt();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads a claims proof verifier from a PKV file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the verifier cannot be deserialized.
pub fn load_claims_verifier_from_path(path: impl AsRef<Path>) -> eyre::Result<ClaimsVerifier> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Generates a claims proof using artifacts from the provided source.
///
/// # Errors
/// Returns an error if inputs are invalid, artifacts cannot be loaded, or proving fails.
pub fn generate_claims_proof(
    input: ClaimsProofInput<'_>,
    artifacts: &dyn ZkArtifactSource,
) -> Result<ClaimsProof, ProofError> {
    let prover = artifacts.claims_prover()?;
    generate_claims_proof_with_prover(input, prover)
}

/// Generates a claims proof using the provided prover.
///
/// # Errors
/// Returns an error if inputs are invalid, witness generation fails, or proving fails.
pub fn generate_claims_proof_with_prover(
    input: ClaimsProofInput<'_>,
    prover: ClaimsProver,
) -> Result<ClaimsProof, ProofError> {
    validate_input(&input)?;
    provekit_common::register_ntt();

    let witness = into_witness(&input)?;
    let noir_proof = prover
        .prove(witness)
        .map_err(|e| ProofError::GenerationError(e.to_string()))?;

    Ok(ClaimsProof {
        proof: noir_proof.whir_r1cs_proof,
        statements: input.request.statements.clone(),
    })
}

/// Verifies a claims proof using artifacts from the provided source.
///
/// The caller must obtain `context` from the same RP request, issuer registry lookup, and
/// nullifier-proof response that it independently verifies.
///
/// # Errors
/// Returns an error if artifacts cannot be loaded, inputs are invalid, or verification fails.
pub fn verify_claims_proof(
    proof: &ClaimsProof,
    context: &ClaimsProofContext,
    artifacts: &dyn ZkArtifactSource,
) -> Result<(), ProofError> {
    let mut verifier = artifacts.claims_verifier()?;
    verify_claims_proof_with_verifier(proof, context, &mut verifier)
}

/// Verifies the claims co-proof attached to a nullifier-proof response item.
///
/// This is the RP-facing seam: it reconstructs every public input shared with the companion
/// nullifier proof from the original request and response. The caller must independently verify
/// `response.proof` as the Circom nullifier proof and resolve `credential_public_key` from the
/// issuer/schema registry.
///
/// # Errors
/// Returns an error if the request and response do not match, no claims proof is attached, or the
/// claims proof fails verification. The RP must still validate the complete response and verify its
/// companion Circom proof independently.
pub fn verify_claims_proof_for_response(
    request: &ProofRequest,
    response: &ResponseItem,
    credential_public_key: EdDSAPublicKey,
    artifacts: &dyn ZkArtifactSource,
) -> Result<(), ProofError> {
    let request_item = request
        .requests
        .iter()
        .find(|item| item.identifier == response.identifier)
        .ok_or_else(|| ProofError::InternalError(eyre::eyre!("response item was not requested")))?;
    if request_item.issuer_schema_id != response.issuer_schema_id {
        return Err(ProofError::InternalError(eyre::eyre!(
            "response issuer schema does not match request"
        )));
    }
    if request.proof_type.is_session() != response.is_session() {
        return Err(ProofError::InternalError(eyre::eyre!(
            "response proof type does not match request"
        )));
    }
    let expected_expires_at_min = request_item.effective_expires_at_min(request.created_at);
    if response.expires_at_min != expected_expires_at_min {
        return Err(ProofError::InternalError(eyre::eyre!(
            "response credential time policy does not match request"
        )));
    }
    let proof = response.claims_proof.as_ref().ok_or_else(|| {
        ProofError::InternalError(eyre::eyre!("response item has no claims proof"))
    })?;
    let requested_statements = &request_item
        .claims
        .as_ref()
        .ok_or_else(|| {
            ProofError::InternalError(eyre::eyre!("request item did not ask for a claims proof"))
        })?
        .statements;
    if requested_statements != &proof.statements {
        return Err(ProofError::InternalError(eyre::eyre!(
            "claims proof statements do not match request"
        )));
    }

    let (nullifier, action) = match (&response.nullifier, &response.session_nullifier) {
        (Some(nullifier), None) => (
            nullifier.inner,
            request.action.ok_or_else(|| {
                ProofError::InternalError(eyre::eyre!("uniqueness request has no nullifier action"))
            })?,
        ),
        (None, Some(session_nullifier)) => {
            (session_nullifier.nullifier(), session_nullifier.action())
        }
        _ => {
            return Err(ProofError::InternalError(eyre::eyre!(
                "response must contain exactly one nullifier type"
            )));
        }
    };

    verify_claims_proof(
        proof,
        &ClaimsProofContext {
            issuer_schema_id: request_item.issuer_schema_id.into(),
            credential_public_key,
            current_timestamp: response.expires_at_min.into(),
            cred_genesis_issued_at_min: request_item.genesis_issued_at_min.unwrap_or(0).into(),
            nullifier,
            rp_id: request.rp_id.into(),
            action,
        },
        artifacts,
    )
}

/// Verifies a claims proof using the provided verifier.
///
/// # Errors
/// Returns an error if public inputs are invalid or verification fails.
pub fn verify_claims_proof_with_verifier(
    proof: &ClaimsProof,
    context: &ClaimsProofContext,
    verifier: &mut ClaimsVerifier,
) -> Result<(), ProofError> {
    validate_statements(&proof.statements)?;

    provekit_common::register_ntt();
    let public_inputs = PublicInputs::from_vec(public_inputs(proof, context));
    verifier
        .verify(&NoirProof {
            public_inputs,
            whir_r1cs_proof: proof.proof.clone(),
        })
        .map_err(|e| ProofError::Verification(e.to_string()))
}

fn validate_input(input: &ClaimsProofInput<'_>) -> Result<(), ProofError> {
    validate_statements(&input.request.statements)?;
    if input.credential.signature.is_none() {
        return Err(ProofError::InternalError(eyre::eyre!(
            "credential not signed"
        )));
    }
    if input.credential.issuer_schema_id != u64::try_from(input.context.issuer_schema_id)? {
        return Err(ProofError::InternalError(eyre::eyre!(
            "claims proof issuer schema does not match credential"
        )));
    }
    if input.credential.issuer != input.context.credential_public_key {
        return Err(ProofError::InternalError(eyre::eyre!(
            "claims proof issuer key does not match credential"
        )));
    }
    Ok(())
}

fn validate_statements(statements: &[ClaimStatement]) -> Result<(), ProofInputError> {
    let mut seen = [false; Credential::MAX_CLAIMS];
    for statement in statements {
        let index = usize::from(statement.claim_index);
        if index >= Credential::MAX_CLAIMS {
            return Err(ProofInputError::InvalidClaimIndex {
                index: statement.claim_index,
            });
        }
        if std::mem::replace(&mut seen[index], true) {
            return Err(ProofInputError::DuplicateClaimIndex {
                index: statement.claim_index,
            });
        }
        if statement.min_exclusive.is_none() && statement.max_exclusive.is_none() {
            return Err(ProofInputError::EmptyClaimStatement {
                index: statement.claim_index,
            });
        }
    }
    Ok(())
}

fn expanded_statements(
    statements: &[ClaimStatement],
) -> [(bool, bool, FieldElement, FieldElement); Credential::MAX_CLAIMS] {
    let mut expanded =
        [(false, false, FieldElement::ZERO, FieldElement::ZERO); Credential::MAX_CLAIMS];
    for statement in statements {
        let index = usize::from(statement.claim_index);
        expanded[index] = (
            statement.min_exclusive.is_some(),
            statement.max_exclusive.is_some(),
            statement.min_exclusive.unwrap_or(FieldElement::ZERO),
            statement.max_exclusive.unwrap_or(FieldElement::ZERO),
        );
    }
    expanded
}

fn statement_values(statements: &[ClaimStatement]) -> Vec<InputValue> {
    expanded_statements(statements)
        .into_iter()
        .map(|(check_min, check_max, min, max)| {
            let mut statement = BTreeMap::new();
            statement.insert(
                "checks".into(),
                InputValue::Vec(vec![
                    InputValue::Field(NoirElement::from(check_min)),
                    InputValue::Field(NoirElement::from(check_max)),
                ]),
            );
            statement.insert("range_check_min".into(), min.into_noir_value());
            statement.insert("range_check_max".into(), max.into_noir_value());
            InputValue::Struct(statement)
        })
        .collect()
}

fn into_witness(input: &ClaimsProofInput<'_>) -> Result<InputMap, ProofError> {
    let mut claims_public = BTreeMap::new();
    claims_public.insert(
        "statements".into(),
        InputValue::Vec(statement_values(&input.request.statements)),
    );

    let mut credential_public = BTreeMap::new();
    credential_public.insert(
        "issuer_schema_id".into(),
        input.context.issuer_schema_id.into_noir_value(),
    );
    credential_public.insert(
        "cred_pk".into(),
        InputValue::Vec(vec![
            InputValue::Field(NoirElement::from_repr(
                input.context.credential_public_key.pk.x,
            )),
            InputValue::Field(NoirElement::from_repr(
                input.context.credential_public_key.pk.y,
            )),
        ]),
    );
    credential_public.insert(
        "current_timestamp".into(),
        input.context.current_timestamp.into_noir_value(),
    );
    credential_public.insert(
        "cred_genesis_issued_at_min".into(),
        input.context.cred_genesis_issued_at_min.into_noir_value(),
    );

    let mut nullifier_public = BTreeMap::new();
    nullifier_public.insert("value".into(), input.context.nullifier.into_noir_value());
    nullifier_public.insert("rp_id".into(), input.context.rp_id.into_noir_value());
    nullifier_public.insert("action".into(), input.context.action.into_noir_value());

    let mut public = BTreeMap::new();
    public.insert("claims".into(), InputValue::Struct(claims_public));
    public.insert("credential".into(), InputValue::Struct(credential_public));
    public.insert("nullifier".into(), InputValue::Struct(nullifier_public));

    let mut claims = vec![FieldElement::ZERO; Credential::MAX_CLAIMS];
    claims[..input.credential.claims.len()].copy_from_slice(&input.credential.claims);

    let signature = input
        .credential
        .signature
        .as_ref()
        .ok_or_else(|| ProofError::InternalError(eyre::eyre!("credential not signed")))?;
    let signature_s =
        ark_bn254::Fr::from_be_bytes_mod_order(&signature.s.into_bigint().to_bytes_be());
    let cred_id = ark_babyjubjub::Fq::from(BigInt([
        input.credential.id,
        u64::from(input.credential.issuer_version),
        0,
        0,
    ]));

    let mut credential_private = BTreeMap::new();
    credential_private.insert(
        "cred_genesis_issued_at".into(),
        FieldElement::from(input.credential.genesis_issued_at).into_noir_value(),
    );
    credential_private.insert(
        "cred_expires_at".into(),
        FieldElement::from(input.credential.expires_at).into_noir_value(),
    );
    credential_private.insert(
        "associated_data_hash".into(),
        input
            .credential
            .associated_data_commitment
            .into_noir_value(),
    );
    credential_private.insert(
        "cred_id".into(),
        FieldElement::from(cred_id).into_noir_value(),
    );
    credential_private.insert(
        "cred_user_id_r".into(),
        input.credential_sub_blinding_factor.into_noir_value(),
    );
    credential_private.insert(
        "cred_s".into(),
        InputValue::Field(NoirElement::from_repr(signature_s)),
    );
    credential_private.insert(
        "cred_r".into(),
        InputValue::Vec(vec![
            InputValue::Field(NoirElement::from_repr(signature.r.x)),
            InputValue::Field(NoirElement::from_repr(signature.r.y)),
        ]),
    );

    let mut nullifier_private = BTreeMap::new();
    nullifier_private.insert(
        "leaf_index".into(),
        FieldElement::from(input.leaf_index).into_noir_value(),
    );
    nullifier_private.insert(
        "oprf_response".into(),
        InputValue::Vec(vec![
            InputValue::Field(NoirElement::from_repr(input.oprf_response.x)),
            InputValue::Field(NoirElement::from_repr(input.oprf_response.y)),
        ]),
    );

    let mut private = BTreeMap::new();
    private.insert(
        "claims".into(),
        InputValue::Vec(
            claims
                .into_iter()
                .map(|claim| claim.into_noir_value())
                .collect(),
        ),
    );
    private.insert("credential".into(), InputValue::Struct(credential_private));
    private.insert("nullifier".into(), InputValue::Struct(nullifier_private));

    let mut witness = InputMap::new();
    witness.insert("public_inputs".into(), InputValue::Struct(public));
    witness.insert("private_inputs".into(), InputValue::Struct(private));
    Ok(witness)
}

fn public_inputs(proof: &ClaimsProof, context: &ClaimsProofContext) -> Vec<ark_babyjubjub::Fq> {
    let mut values = Vec::with_capacity(68);
    for (check_min, check_max, min, max) in expanded_statements(&proof.statements) {
        values.push(ark_babyjubjub::Fq::from(check_min));
        values.push(ark_babyjubjub::Fq::from(check_max));
        values.push(*min);
        values.push(*max);
    }
    values.extend([
        *context.issuer_schema_id,
        context.credential_public_key.pk.x,
        context.credential_public_key.pk.y,
        *context.current_timestamp,
        *context.cred_genesis_issued_at_min,
        *context.nullifier,
        *context.rp_id,
        *context.action,
    ]);
    values
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "embed-claims-prover", feature = "embed-claims-verifier"))]
    use std::str::FromStr as _;

    #[cfg(all(feature = "embed-claims-prover", feature = "embed-claims-verifier"))]
    use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
    #[cfg(all(feature = "embed-claims-prover", feature = "embed-claims-verifier"))]
    use eddsa_babyjubjub::EdDSASignature;
    #[cfg(all(feature = "embed-claims-prover", feature = "embed-claims-verifier"))]
    use world_id_primitives::CredentialVersion;

    use super::*;

    #[test]
    fn rejects_duplicate_claim_indices() {
        let statement = ClaimStatement {
            claim_index: 2,
            min_exclusive: Some(FieldElement::from(18u64)),
            max_exclusive: None,
        };
        let error = validate_statements(&[statement.clone(), statement]).unwrap_err();
        assert!(matches!(
            error,
            ProofInputError::DuplicateClaimIndex { index: 2 }
        ));
    }

    #[test]
    fn expands_sparse_statements_into_fixed_claim_slots() {
        let statements = [ClaimStatement {
            claim_index: 3,
            min_exclusive: Some(FieldElement::from(17u64)),
            max_exclusive: Some(FieldElement::from(66u64)),
        }];
        let expanded = expanded_statements(&statements);
        assert_eq!(
            expanded[2],
            (false, false, FieldElement::ZERO, FieldElement::ZERO)
        );
        assert_eq!(
            expanded[3],
            (
                true,
                true,
                FieldElement::from(17u64),
                FieldElement::from(66u64)
            )
        );
    }

    #[cfg(all(feature = "embed-claims-prover", feature = "embed-claims-verifier"))]
    fn field(value: &str) -> FieldElement {
        FieldElement::from(Fq::from_str(value).unwrap())
    }

    #[cfg(all(feature = "embed-claims-prover", feature = "embed-claims-verifier"))]
    fn fixture() -> (Credential, FieldElement, EdwardsAffine, ClaimsProofContext) {
        let blinder =
            field("19016519542686775328775746932795543103858066763212549618980890183285781521458");
        let issuer_pk = EdDSAPublicKey {
            pk: EdwardsAffine::new_unchecked(
                Fq::from_str(
                    "21825204959029483311433036009853709113262520481918849765727459753607131160346",
                )
                .unwrap(),
                Fq::from_str(
                    "8339486770249821464793634710648189540136988043780169655155172519121840615364",
                )
                .unwrap(),
            ),
        };
        let credential = Credential {
            id: 12_176_925_761_186_149_284,
            version: CredentialVersion::V1,
            issuer_version: 0,
            issuer_schema_id: 1,
            sub: Credential::compute_sub(1, blinder),
            genesis_issued_at: 1_767_868_120,
            expires_at: 1_767_868_180,
            claims: vec![FieldElement::ZERO; Credential::MAX_CLAIMS],
            associated_data_commitment: FieldElement::ZERO,
            signature: Some(EdDSASignature {
                s: Fr::from_str(
                    "1785197794318390548654263507521729446174585997835004080357493002880021427752",
                )
                .unwrap(),
                r: EdwardsAffine::new_unchecked(
                    Fq::from_str(
                        "9716162517813998269973089361571651784159199085806289463178774674474552458864",
                    )
                    .unwrap(),
                    Fq::from_str(
                        "6858161934880479087336794169055762635352680692798466775715085760374212641424",
                    )
                    .unwrap(),
                ),
            }),
            issuer: issuer_pk.clone(),
        };
        let oprf_response = EdwardsAffine::new_unchecked(
            Fq::from_str(
                "11771927497930831763844779626723106344742708040976110136703486119568919340013",
            )
            .unwrap(),
            Fq::from_str(
                "19299702061490581533153169629464406607119112637706400365988657399831357218309",
            )
            .unwrap(),
        );
        let context = ClaimsProofContext {
            issuer_schema_id: FieldElement::from(1u64),
            credential_public_key: issuer_pk,
            current_timestamp: FieldElement::from(1_767_868_101u64),
            cred_genesis_issued_at_min: FieldElement::ZERO,
            nullifier: field(
                "21342856517406476000190785734870568200315738457615815351702849709270076362125",
            ),
            rp_id: field("950325648507560155068233096743093215539447660945"),
            action: field(
                "84721944028150696728472418813119358007006361082259892623669024918011698311",
            ),
        };
        (credential, blinder, oprf_response, context)
    }

    #[cfg(all(feature = "embed-claims-prover", feature = "embed-claims-verifier"))]
    #[test]
    fn generates_verifies_and_binds_nullifier() {
        use crate::artifacts::embedded::EmbeddedZkArtifacts;

        let (credential, blinder, oprf_response, context) = fixture();
        let request = ClaimsProofRequest {
            statements: vec![ClaimStatement {
                claim_index: 0,
                min_exclusive: None,
                max_exclusive: Some(FieldElement::from(1u64)),
            }],
        };
        let artifacts = EmbeddedZkArtifacts;
        let proof = generate_claims_proof(
            ClaimsProofInput {
                credential: &credential,
                credential_sub_blinding_factor: blinder,
                leaf_index: 1,
                oprf_response,
                context: context.clone(),
                request: &request,
            },
            &artifacts,
        )
        .unwrap();

        verify_claims_proof(&proof, &context, &artifacts).unwrap();

        let mut wrong_context = context;
        wrong_context.nullifier = FieldElement::from(1u64);
        let error = verify_claims_proof(&proof, &wrong_context, &artifacts).unwrap_err();
        assert!(matches!(error, ProofError::Verification(_)));
    }
}
