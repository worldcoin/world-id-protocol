//! WIP-202: Proof of Embedding Similarity using ProveKit (Noir circuit backend).
//!
//! Proves that a WIP-201 Flamingo Token compared a live capture against the PCP thumbnail
//! committed to by the World ID's PoH Credential, and that the World ID authorized the token.

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::{collections::BTreeMap, io::Read};

use ark_ff::PrimeField as _;
use provekit_common::{InputMap, InputValue, NoirElement};
use world_id_flamingo::{FlamingoAatClaims, FlamingoClaims};
use world_id_primitives::{
    Credential, CredentialVersion, EdDSAPublicKey, FieldElement, ProofRequest, ProofType,
    SessionRef, TREE_DEPTH,
    authenticator::oprf_query_digest,
    authenticator_assertion::{AatPublicValues, AatRequirements},
    poseidon::{self, ds},
    proof::EmbeddingSimilarityProof,
    sponge::hash_bytes_to_field_element,
};

use crate::{
    NoirCircuitInput, NoirRepresentable as _, ProofError,
    artifacts::ZkArtifactSource,
    circuit_inputs::{EmbeddingSimilarityCircuitInput, EmbeddingSimilarityRequestInputs},
    error::ProofInputError,
    noir_components::{
        account_inputs, check_account_input_validity, credential_inputs, public_key, signature,
    },
    provekit,
};

/// Shortest accepted `hashes.json` in bytes (`MIN_HASHES_JSON_BYTES` in the circuit).
pub const MIN_HASHES_JSON_BYTES: usize = 3072;
/// Longest accepted `hashes.json` in bytes (`MAX_HASHES_JSON_BYTES` in the circuit).
pub const MAX_HASHES_JSON_BYTES: usize = 5120;
/// Bytes per sponge chunk: 31 bytes stay below the BN254 modulus.
pub(crate) const CHUNK_BYTES: usize = 31;
/// Chunk slots of the circuit's `HashesJsonInputs`: `⌈MAX_HASHES_JSON_BYTES / 31⌉` (WIP-202 §4.5).
pub(crate) const CHUNK_SLOTS: usize = MAX_HASHES_JSON_BYTES.div_ceil(CHUNK_BYTES);
/// The key of the thumbnail entry; the byte before it must be `{` or `,`.
pub(crate) const THUMBNAIL_KEY: &[u8] = b"\"thumbnail.png\":\"";
/// Hex digits of a SHA-256 digest.
pub(crate) const DIGEST_HEX_LEN: usize = 64;
/// The `compare_sources` WIP-202 fixes: compared entry 1 is pipeline input 0.
pub const COMPARE_SOURCES: u32 = 256;
/// Credential claim holding the `hashes.json` commitment.
pub(crate) const CLAIM_INDEX: usize = 0;

/// Loads an embedding similarity prover from a reader containing PKP bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the prover cannot be deserialized.
pub fn load_embedding_similarity_prover_from_reader(
    reader: impl Read,
) -> eyre::Result<provekit_common::Prover> {
    provekit::load_prover_from_reader(reader)
}

/// Loads an embedding similarity prover from a PKP file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the prover cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_embedding_similarity_prover_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Prover> {
    provekit::load_prover_from_path(path)
}

/// Loads an embedding similarity verifier from a reader containing PKV bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the verifier cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_embedding_similarity_verifier_from_reader(
    reader: impl Read,
) -> eyre::Result<provekit_common::Verifier> {
    provekit::load_verifier_from_reader(reader)
}

/// Loads an embedding similarity verifier from a PKV file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the verifier cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_embedding_similarity_verifier_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Verifier> {
    provekit::load_verifier_from_path(path)
}

/// The byte offset of the thumbnail digest in `hashes.json`, and the digest `R(d)` it encodes.
///
/// Takes the first `thumbnail.png` key. The circuit accepts any, which is the same entry for the
/// compact, flat `hashes.json` with unique keys that orb-core writes (WIP-202 §4.1).
fn thumbnail_digest(hashes_json: &[u8]) -> Result<(usize, FieldElement), ProofInputError> {
    let invalid = |reason| ProofInputError::InvalidHashesJson { reason };

    let key_start = (1..hashes_json.len())
        .find(|&i| {
            matches!(hashes_json[i - 1], b'{' | b',') && hashes_json[i..].starts_with(THUMBNAIL_KEY)
        })
        .ok_or_else(|| invalid("no thumbnail.png entry"))?;
    let offset = key_start + THUMBNAIL_KEY.len();
    let digest_hex = hashes_json
        .get(offset..offset + DIGEST_HEX_LEN)
        .ok_or_else(|| invalid("thumbnail digest exceeds the file"))?;
    if hashes_json.get(offset + DIGEST_HEX_LEN) != Some(&b'"') {
        return Err(invalid("thumbnail digest must be 64 hex digits"));
    }

    let mut digest = ark_babyjubjub::Fq::from(0u64);
    for &c in digest_hex {
        let nibble = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return Err(invalid("thumbnail digest must be lowercase hex")),
        };
        digest = digest * ark_babyjubjub::Fq::from(16u64) + ark_babyjubjub::Fq::from(nibble);
    }
    Ok((offset, digest.into()))
}

/// Encodes the `HashesJsonInputs`: 31-byte big-endian chunks, zero-padded to the slots.
fn hashes_json_inputs(hashes_json: &[u8]) -> Result<InputValue, ProofInputError> {
    if !(MIN_HASHES_JSON_BYTES..=MAX_HASHES_JSON_BYTES).contains(&hashes_json.len()) {
        return Err(ProofInputError::InvalidHashesJson {
            reason: "length is outside the accepted range",
        });
    }
    let (digest_offset, _) = thumbnail_digest(hashes_json)?;

    let mut chunks: Vec<InputValue> = hashes_json
        .chunks(CHUNK_BYTES)
        .map(|chunk| {
            FieldElement::from(ark_babyjubjub::Fq::from_be_bytes_mod_order(chunk)).into_noir_value()
        })
        .collect();
    chunks.resize(CHUNK_SLOTS, FieldElement::ZERO.into_noir_value());

    let mut fields = BTreeMap::new();
    fields.insert("chunks".into(), InputValue::Vec(chunks));
    fields.insert(
        "len".into(),
        InputValue::Field(NoirElement::from(hashes_json.len() as u64)),
    );
    fields.insert(
        "digest_offset".into(),
        InputValue::Field(NoirElement::from(digest_offset as u64)),
    );
    Ok(InputValue::Struct(fields))
}

impl EmbeddingSimilarityRequestInputs {
    /// The RP's public inputs of a WIP-202 request (WIP-202 §4.4), with the `issuer_version` the
    /// RP accepts, which the request format can't express yet.
    ///
    /// # Errors
    /// Returns [`ProofInputError::InvalidEmbeddingSimilarityRequest`] if `request` is not a valid
    /// Proof of Embedding Similarity request.
    pub fn from_request(
        request: &ProofRequest,
        issuer_version: u8,
    ) -> Result<Self, ProofInputError> {
        request.validate_proof_type().map_err(|e| {
            ProofInputError::InvalidEmbeddingSimilarityRequest {
                reason: e.to_string(),
            }
        })?;
        let ProofType::EmbeddingSimilarity(params) = &request.proof_type else {
            return Err(ProofInputError::InvalidEmbeddingSimilarityRequest {
                reason: "it requests another proof type".to_string(),
            });
        };
        // `validate_proof_type` guarantees exactly one request item.
        let item = &request.requests[0];
        Ok(Self {
            rp_id: request.rp_id.into(),
            nonce: request.nonce,
            challenge_hash: params.challenge_hash,
            signal_hash: item.signal_hash(),
            session_id: match request.session_id {
                SessionRef::Existing(session_id) => session_id.commitment,
                SessionRef::Create | SessionRef::None => FieldElement::ZERO,
            },
            issuer_schema_id: item.issuer_schema_id,
            issuer_version,
            genesis_issued_at_min: item.genesis_issued_at_min.unwrap_or(0),
            expires_at_min: item.effective_expires_at_min(request.created_at),
        })
    }
}

/// The WIP-201 digest of the Flamingo Token the circuit verifies.
fn token_digest<const MAX_DEPTH: usize>(
    inputs: &EmbeddingSimilarityCircuitInput<MAX_DEPTH>,
) -> Result<FieldElement, ProofInputError> {
    let request = &inputs.request;
    let (_, credential_digest) = thumbnail_digest(&inputs.hashes_json)?;
    Ok(FlamingoClaims {
        now: inputs.now,
        compared_entry_hashes: [
            credential_digest,
            inputs.live_capture_hash,
            request.challenge_hash,
            FieldElement::ZERO,
        ],
        aud: request.rp_id,
        nonce: request.nonce,
        // `sec_flags` layout with `min_build_version` (bits 16-47) fixed to 0 by WIP-202.
        aat: inputs.aat.as_ref().map(|aat| FlamingoAatClaims {
            trust_anchor_key_hash: aat.trust_anchor_key_hash,
            aat_flags: u64::from(aat.platform)
                | (u64::from(aat.sec_level) << 8)
                | (u64::from(aat.sec_meta) << 48)
                | (u64::from(aat.authenticator_meta) << 52),
        }),
        compare_sources: COMPARE_SOURCES,
        engine_config_hash: inputs.engine_config_hash,
        billing_nullifier: inputs.billing_nullifier,
    }
    .digest())
}

/// Checks the embedding similarity inputs by emulating the constraints the circuit enforces, so a
/// caller mistake surfaces as a specific error instead of an opaque proving failure. This is only
/// for error convenience, the actual constraints are verified in the circuit.
///
/// # Errors
/// Returns a [`ProofInputError`] if any check fails.
pub fn check_embedding_similarity_input_validity<const MAX_DEPTH: usize>(
    inputs: &EmbeddingSimilarityCircuitInput<MAX_DEPTH>,
) -> Result<(), ProofInputError> {
    let request = &inputs.request;
    let leaf_index = inputs.inclusion_proof.leaf_index;

    // 1. The challenge must be present: `0` marks an unused compared entry.
    if request.challenge_hash == FieldElement::ZERO {
        return Err(ProofInputError::ValueMustNotBeZero {
            name: "challenge_hash",
        });
    }

    // 2. `hashes.json` must fit the circuit, before its thumbnail digest is read below.
    hashes_json_inputs(&inputs.hashes_json)?;

    // 3. The AAT values must fit their claim widths, as the token library range-checks them.
    if let Some(aat) = &inputs.aat {
        let widths = [
            ("sec_meta", aat.sec_meta, AatRequirements::SEC_META_BITS),
            (
                "authenticator_meta",
                aat.authenticator_meta,
                AatRequirements::AUTHENTICATOR_META_BITS,
            ),
        ];
        for (name, value, bits) in widths {
            if u32::from(value) >> bits != 0 {
                return Err(ProofInputError::ValueOutOfBounds {
                    name,
                    is: u64::from(value).into(),
                    limit: (1u64 << bits).into(),
                });
            }
        }
        // WIP-106 reserves `user_presence` (bits 0-2 of `authenticator_meta`) values 5 to 7.
        let user_presence = aat.authenticator_meta & 7;
        if user_presence >= 5 {
            return Err(ProofInputError::ReservedUserPresence { user_presence });
        }
    }

    // 4. The Flamingo Verifier must have signed the token.
    let digest = token_digest(inputs)?;
    if !inputs
        .flamingo_verifier_key
        .verify(*digest, &inputs.token_signature)
    {
        return Err(ProofInputError::InvalidFlamingoTokenSignature);
    }

    // 5. A registered key of the World ID must have authorized the token and the RP's signal.
    let key =
        check_account_input_validity(&inputs.key_set, inputs.key_index, &inputs.inclusion_proof)?;
    let message = poseidon::hash(
        ds::EMBEDDING_SIMILARITY_AUTH,
        [
            digest,
            inputs.flamingo_verifier_key.pk.x.into(),
            inputs.flamingo_verifier_key.pk.y.into(),
            request.signal_hash,
        ],
    );
    if !key.verify(*message, &inputs.signature) {
        return Err(ProofInputError::InvalidAuthenticatorSignature);
    }

    // 6. The session ID is either absent or this World ID's session commitment.
    let session_commitment = poseidon::hash(
        ds::SESSION_COMMITMENT,
        [leaf_index.into(), inputs.session_id_r],
    );
    if request.session_id != FieldElement::ZERO && request.session_id != session_commitment {
        return Err(ProofInputError::InvalidSessionId);
    }

    // 7. The issuer must have signed the World ID's PoH Credential, which must be valid.
    let credential = Credential {
        id: inputs.credential_id,
        version: CredentialVersion::V1,
        issuer_version: request.issuer_version,
        issuer_schema_id: request.issuer_schema_id,
        sub: Credential::compute_sub(leaf_index, inputs.sub_blinding_factor),
        genesis_issued_at: inputs.genesis_issued_at,
        expires_at: inputs.expires_at,
        claims: inputs.claims.to_vec(),
        associated_data_commitment: inputs.associated_data_hash,
        signature: Some(inputs.credential_signature.clone()),
        issuer: inputs.cred_pk.clone(),
    };
    if !credential
        .verify_signature(&inputs.cred_pk)
        .map_err(|_| ProofInputError::InvalidCredentialSignature)?
    {
        return Err(ProofInputError::InvalidCredentialSignature);
    }
    if u64::from(inputs.now) >= inputs.expires_at {
        return Err(ProofInputError::CredentialExpired {
            current_timestamp: inputs.now.into(),
            expires_at: inputs.expires_at,
        });
    }
    if request.genesis_issued_at_min > inputs.genesis_issued_at {
        return Err(ProofInputError::CredentialGenesisExpired {
            genesis_issued_at_min: request.genesis_issued_at_min,
            genesis_issued_at: inputs.genesis_issued_at,
        });
    }
    // As for Uniqueness and Session Proofs, `expires_at_min` is the time the Credential must outlive.
    if request.expires_at_min >= inputs.expires_at {
        return Err(ProofInputError::CredentialExpired {
            current_timestamp: request.expires_at_min,
            expires_at: inputs.expires_at,
        });
    }

    // 8. The billing nullifier is `0` or this World ID's WIP-107 nullifier for the RP.
    if inputs.billing_nullifier != FieldElement::ZERO {
        let query = oprf_query_digest(leaf_index, inputs.billing_action, request.rp_id);
        let own_nullifier = poseidon::hash(
            ds::OPRF_PROOF,
            [
                query,
                inputs.billing_oprf_output[0],
                inputs.billing_oprf_output[1],
            ],
        );
        if inputs.billing_nullifier != own_nullifier {
            return Err(ProofInputError::InvalidBillingNullifier);
        }
    }

    // 9. The Credential claim must commit to `hashes.json`.
    let claim = hash_bytes_to_field_element(ds::CLAIMS_HASH_V1, &inputs.hashes_json)
        .map_err(|_| ProofInputError::InvalidHashesJsonClaim)?;
    if inputs.claims[CLAIM_INDEX] != claim {
        return Err(ProofInputError::InvalidHashesJsonClaim);
    }

    Ok(())
}

/// The public inputs the prover chooses, which [`EmbeddingSimilarityProof`] carries.
struct ProverChosen<'a> {
    now: u32,
    flamingo_verifier_key: &'a EdDSAPublicKey,
    engine_config_hash: FieldElement,
    aat: Option<&'a AatPublicValues>,
    merkle_root: FieldElement,
    cred_pk: &'a EdDSAPublicKey,
}

impl<'a> ProverChosen<'a> {
    fn of_input<const MAX_DEPTH: usize>(
        input: &'a EmbeddingSimilarityCircuitInput<MAX_DEPTH>,
    ) -> Self {
        Self {
            now: input.now,
            flamingo_verifier_key: &input.flamingo_verifier_key,
            engine_config_hash: input.engine_config_hash,
            aat: input.aat.as_ref(),
            merkle_root: input.inclusion_proof.root,
            cred_pk: &input.cred_pk,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn of_proof(proof: &'a EmbeddingSimilarityProof) -> Self {
        Self {
            now: proof.now,
            flamingo_verifier_key: &proof.flamingo_verifier_key,
            engine_config_hash: proof.engine_config_hash,
            aat: proof.aat.as_ref(),
            merkle_root: proof.merkle_root,
            cred_pk: &proof.cred_pk,
        }
    }
}

/// The public inputs in the order of the circuit's `main` parameters.
fn public_witness(
    request: &EmbeddingSimilarityRequestInputs,
    chosen: &ProverChosen<'_>,
) -> [(&'static str, InputValue); 20] {
    let field = |value: u64| InputValue::Field(NoirElement::from(value));
    // Without an AAT, the circuit takes every AAT value as `0`.
    let zero = FieldElement::ZERO;
    let (trust_anchor_key_hash, platform, sec_level, sec_meta, authenticator_meta) =
        chosen.aat.map_or((zero, 0, 0, 0, 0), |aat| {
            (
                aat.trust_anchor_key_hash,
                aat.platform,
                aat.sec_level,
                aat.sec_meta,
                aat.authenticator_meta,
            )
        });
    [
        ("now", field(chosen.now.into())),
        ("rp_id", request.rp_id.into_noir_value()),
        ("nonce", request.nonce.into_noir_value()),
        ("challenge_hash", request.challenge_hash.into_noir_value()),
        ("signal_hash", request.signal_hash.into_noir_value()),
        ("session_id", request.session_id.into_noir_value()),
        (
            "flamingo_verifier_key",
            public_key(&chosen.flamingo_verifier_key.pk),
        ),
        (
            "engine_config_hash",
            chosen.engine_config_hash.into_noir_value(),
        ),
        ("has_aat", field(chosen.aat.is_some().into())),
        (
            "trust_anchor_key_hash",
            trust_anchor_key_hash.into_noir_value(),
        ),
        ("platform", field(platform.into())),
        ("sec_level", field(sec_level.into())),
        ("sec_meta", field(sec_meta.into())),
        ("authenticator_meta", field(authenticator_meta.into())),
        ("merkle_root", chosen.merkle_root.into_noir_value()),
        ("issuer_schema_id", field(request.issuer_schema_id)),
        ("issuer_version", field(request.issuer_version.into())),
        ("cred_pk", public_key(&chosen.cred_pk.pk)),
        (
            "genesis_issued_at_min",
            field(request.genesis_issued_at_min),
        ),
        ("expires_at_min", field(request.expires_at_min)),
    ]
}

impl NoirCircuitInput for EmbeddingSimilarityCircuitInput<TREE_DEPTH> {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        let mut map: InputMap = public_witness(&self.request, &ProverChosen::of_input(&self))
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect();

        let mut token = BTreeMap::new();
        token.insert(
            "live_capture_hash".into(),
            self.live_capture_hash.into_noir_value(),
        );
        token.insert(
            "billing_nullifier".into(),
            self.billing_nullifier.into_noir_value(),
        );
        token.insert("sig".into(), signature(&self.token_signature));

        let mut inputs = BTreeMap::new();
        inputs.insert("token".into(), InputValue::Struct(token));
        inputs.insert(
            "account".into(),
            account_inputs(
                &self.key_set,
                self.key_index,
                &self.signature,
                &self.inclusion_proof,
            ),
        );
        inputs.insert(
            "credential".into(),
            credential_inputs(
                &self.claims,
                self.associated_data_hash,
                self.genesis_issued_at,
                self.expires_at,
                self.sub_blinding_factor,
                self.credential_id,
                &self.credential_signature,
            ),
        );
        inputs.insert("hashes_json".into(), hashes_json_inputs(&self.hashes_json)?);
        inputs.insert("session_id_r".into(), self.session_id_r.into_noir_value());
        inputs.insert(
            "billing_action".into(),
            self.billing_action.into_noir_value(),
        );
        inputs.insert(
            "billing_oprf_output".into(),
            InputValue::Vec(
                self.billing_oprf_output
                    .map(|v| v.into_noir_value())
                    .to_vec(),
            ),
        );

        map.insert("inputs".into(), InputValue::Struct(inputs));
        Ok(map)
    }
}

/// Generates an embedding similarity proof using artifacts from the provided source.
///
/// # Errors
/// Returns [`ProofError`] if Noir artifacts cannot be loaded or proving fails.
pub fn generate_embedding_similarity_proof(
    input: EmbeddingSimilarityCircuitInput<TREE_DEPTH>,
    artifacts: &dyn ZkArtifactSource,
) -> Result<EmbeddingSimilarityProof, ProofError> {
    let prover = artifacts.embedding_similarity_prover()?;
    generate_embedding_similarity_proof_with_prover(input, prover)
}

/// Generates an embedding similarity proof using the provided prover.
///
/// # Errors
/// Returns [`ProofError`] if the inputs are invalid, or witness generation or proving fails.
pub fn generate_embedding_similarity_proof_with_prover(
    input: EmbeddingSimilarityCircuitInput<TREE_DEPTH>,
    prover: provekit_common::Prover,
) -> Result<EmbeddingSimilarityProof, ProofError> {
    check_embedding_similarity_input_validity(&input)?;

    let merkle_root = input.inclusion_proof.root;
    let (now, flamingo_verifier_key, engine_config_hash, aat, cred_pk) = (
        input.now,
        input.flamingo_verifier_key.clone(),
        input.engine_config_hash,
        input.aat.clone(),
        input.cred_pk.clone(),
    );
    let proof = provekit::prove(prover, input.into_witness()?)?;

    Ok(EmbeddingSimilarityProof {
        proof,
        now,
        flamingo_verifier_key,
        engine_config_hash,
        aat,
        merkle_root,
        cred_pk,
    })
}

/// Verifies an embedding similarity proof using artifacts from the provided source.
///
/// This is WIP-202 §4.8 item 1 only. The RP must also check items 2-7 itself: the Flamingo Token
/// values, including the Verifier's attestation and the Engine configuration (2), the freshness
/// of `now` (3), the `merkle_root` and the Issuer key (4), that `request` and the challenge image
/// are its own (5), the session (6), and its AAT policy (7).
///
/// # Errors
/// Returns an error if Noir artifacts cannot be loaded, the proof bytes are malformed,
/// or verification fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_embedding_similarity_proof(
    proof: &EmbeddingSimilarityProof,
    request: &EmbeddingSimilarityRequestInputs,
    artifacts: &dyn ZkArtifactSource,
) -> Result<(), ProofError> {
    let mut verifier = artifacts.embedding_similarity_verifier()?;
    verify_embedding_similarity_proof_with_verifier(proof, request, &mut verifier)
}

/// Verifies an embedding similarity proof using the provided verifier. Like
/// [`verify_embedding_similarity_proof`], it checks only WIP-202 §4.8 item 1.
///
/// # Errors
/// Returns an error if the proof bytes are malformed or verification fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_embedding_similarity_proof_with_verifier(
    proof: &EmbeddingSimilarityProof,
    request: &EmbeddingSimilarityRequestInputs,
    verifier: &mut provekit_common::Verifier,
) -> Result<(), ProofError> {
    // A `PublicKey` flattens to `x, y`, its declaration order, which `BTreeMap` order matches.
    let public_inputs: Vec<FieldElement> = public_witness(request, &ProverChosen::of_proof(proof))
        .into_iter()
        .flat_map(|(name, value)| match value {
            InputValue::Field(element) => vec![FieldElement::from(element.into_repr())],
            InputValue::Struct(coordinates) => coordinates
                .into_values()
                .map(|coordinate| match coordinate {
                    InputValue::Field(element) => FieldElement::from(element.into_repr()),
                    _ => unreachable!("`{name}` is a public key of field coordinates"),
                })
                .collect(),
            _ => unreachable!("`{name}` is a field element or a public key"),
        })
        .collect();
    provekit::verify(verifier, &public_inputs, &proof.proof)
}

#[cfg(test)]
mod request_inputs_tests {
    use ruint::aliases::{U160, U256};
    use taceo_oprf::types::OprfKeyId;
    use world_id_primitives::{
        EmbeddingSimilarityParams, OprfPrefix, POH_ISSUER_SCHEMA_ID, RequestItem, RequestVersion,
        SessionId, rp::RpId,
    };

    use super::*;

    const CREATED_AT: u64 = 1_735_689_600;

    fn prefixed(prefix: OprfPrefix, n: u64) -> FieldElement {
        FieldElement::try_from(U256::from(n) | (U256::from(prefix as u8) << 248)).unwrap()
    }

    fn request(proof_type: ProofType, session_id: SessionRef, item: RequestItem) -> ProofRequest {
        ProofRequest {
            id: "req_es".into(),
            version: RequestVersion::V1,
            proof_type,
            session_id,
            created_at: CREATED_AT,
            expires_at: CREATED_AT + 300,
            rp_id: RpId::new(7),
            oprf_key_id: OprfKeyId::new(U160::from(7)),
            signature: alloy_primitives::Signature::test_signature(),
            nonce: FieldElement::from(42_u64),
            requests: vec![item],
            constraints: None,
        }
    }

    fn embedding_similarity() -> ProofType {
        ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
            action: prefixed(OprfPrefix::EmbeddingSimilarity, 1),
            challenge_hash: FieldElement::from(9_u64),
            aat: None,
        })
    }

    #[test]
    fn test_maps_the_request() {
        let item = RequestItem::embedding_similarity(
            "poh".into(),
            Some(b"signal".to_vec()),
            Some(1_000),
            Some(CREATED_AT + 60),
        );
        let inputs = EmbeddingSimilarityRequestInputs::from_request(
            &request(embedding_similarity(), SessionRef::None, item.clone()),
            3,
        )
        .unwrap();
        assert_eq!(
            inputs,
            EmbeddingSimilarityRequestInputs {
                rp_id: FieldElement::from(7_u64),
                nonce: FieldElement::from(42_u64),
                challenge_hash: FieldElement::from(9_u64),
                signal_hash: item.signal_hash(),
                session_id: FieldElement::ZERO,
                issuer_schema_id: POH_ISSUER_SCHEMA_ID,
                issuer_version: 3,
                genesis_issued_at_min: 1_000,
                expires_at_min: CREATED_AT + 60,
            }
        );
    }

    #[test]
    fn test_defaults_the_credential_policy() {
        let item = RequestItem::embedding_similarity("poh".into(), None, None, None);
        let inputs = EmbeddingSimilarityRequestInputs::from_request(
            &request(embedding_similarity(), SessionRef::None, item),
            1,
        )
        .unwrap();
        assert_eq!(inputs.signal_hash, FieldElement::ZERO);
        assert_eq!(inputs.genesis_issued_at_min, 0);
        assert_eq!(inputs.expires_at_min, CREATED_AT);
    }

    #[test]
    fn test_maps_an_existing_session_to_its_commitment() {
        let session = SessionId::new(
            FieldElement::from(5_u64),
            prefixed(OprfPrefix::SessionOprfSeed, 6),
        )
        .unwrap();
        let item = RequestItem::embedding_similarity("poh".into(), None, None, None);
        let inputs = EmbeddingSimilarityRequestInputs::from_request(
            &request(embedding_similarity(), SessionRef::Existing(session), item),
            1,
        )
        .unwrap();
        assert_eq!(inputs.session_id, FieldElement::from(5_u64));
    }

    #[test]
    fn test_rejects_another_proof_type() {
        let item = RequestItem::embedding_similarity("poh".into(), None, None, None);
        let uniqueness = ProofType::Uniqueness {
            action: prefixed(OprfPrefix::Uniqueness, 1),
        };
        let err = EmbeddingSimilarityRequestInputs::from_request(
            &request(uniqueness, SessionRef::None, item),
            1,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::InvalidEmbeddingSimilarityRequest { .. }
        ));
    }

    #[test]
    fn test_rejects_an_invalid_embedding_similarity_request() {
        let other_credential =
            RequestItem::new("poh".into(), POH_ISSUER_SCHEMA_ID + 1, None, None, None);
        let err = EmbeddingSimilarityRequestInputs::from_request(
            &request(embedding_similarity(), SessionRef::None, other_credential),
            1,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::InvalidEmbeddingSimilarityRequest { .. }
        ));
    }
}

#[cfg(test)]
mod input_validation_tests {
    use super::*;

    use crate::embedding_similarity_fixtures::{
        embedding_similarity_billed_fixture, embedding_similarity_fixture, resign,
    };

    fn check(input: &EmbeddingSimilarityCircuitInput<TREE_DEPTH>) -> ProofInputError {
        check_embedding_similarity_input_validity(input).unwrap_err()
    }

    #[test]
    fn test_accepts_the_valid_fixtures() {
        check_embedding_similarity_input_validity(&embedding_similarity_fixture())
            .expect("fixture is valid");
        check_embedding_similarity_input_validity(&embedding_similarity_billed_fixture())
            .expect("billed fixture is valid");
    }

    #[test]
    fn test_rejects_zero_challenge_hash() {
        let mut input = embedding_similarity_fixture();
        input.request.challenge_hash = FieldElement::ZERO;
        resign(&mut input);
        assert!(matches!(
            check(&input),
            ProofInputError::ValueMustNotBeZero {
                name: "challenge_hash"
            }
        ));
    }

    #[test]
    fn test_accepts_a_token_without_an_aat() {
        let mut input = embedding_similarity_fixture();
        input.aat = None;
        resign(&mut input);
        check_embedding_similarity_input_validity(&input).expect("a token without an AAT is valid");
    }

    #[test]
    fn test_rejects_aat_values_wider_than_their_claims() {
        // `sec_meta = 19` packs like `sec_meta = 3` with `authenticator_meta` bit 0 set, so the
        // token signature alone would not catch it.
        let mut input = embedding_similarity_fixture();
        input.aat.as_mut().unwrap().sec_meta = 16;
        assert!(matches!(
            check(&input),
            ProofInputError::ValueOutOfBounds {
                name: "sec_meta",
                ..
            }
        ));

        let mut input = embedding_similarity_fixture();
        input.aat.as_mut().unwrap().authenticator_meta = 32;
        assert!(matches!(
            check(&input),
            ProofInputError::ValueOutOfBounds {
                name: "authenticator_meta",
                ..
            }
        ));
    }

    #[test]
    fn test_rejects_a_reserved_user_presence() {
        let mut input = embedding_similarity_fixture();
        input.aat.as_mut().unwrap().authenticator_meta = 0b01_101;
        resign(&mut input);
        assert!(matches!(
            check(&input),
            ProofInputError::ReservedUserPresence { user_presence: 5 }
        ));
    }

    #[test]
    fn test_reports_the_length_of_a_short_hashes_json_before_its_thumbnail() {
        let mut input = embedding_similarity_fixture();
        input.hashes_json.truncate(100);
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidHashesJson {
                reason: "length is outside the accepted range"
            }
        ));
    }

    #[test]
    fn test_rejects_a_token_over_another_live_capture() {
        let mut input = embedding_similarity_fixture();
        input.live_capture_hash = FieldElement::from(1_u64);
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidFlamingoTokenSignature
        ));
    }

    #[test]
    fn test_rejects_an_authorization_over_another_signal() {
        let mut input = embedding_similarity_fixture();
        input.request.signal_hash = FieldElement::from(1_u64);
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidAuthenticatorSignature
        ));
    }

    #[test]
    fn test_rejects_an_inactive_key_slot() {
        let mut input = embedding_similarity_fixture();
        input.key_index = 1;
        assert!(matches!(
            check(&input),
            ProofInputError::InactiveAuthenticatorKey { index: 1 }
        ));
    }

    #[test]
    fn test_rejects_a_key_set_outside_the_registry() {
        let mut input = embedding_similarity_fixture();
        input.inclusion_proof.root = FieldElement::from(12345_u64);
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidMerkleTreeInclusionProof
        ));
    }

    #[test]
    fn test_rejects_a_session_of_another_blinding_factor() {
        let mut input = embedding_similarity_fixture();
        input.session_id_r = FieldElement::from(1_u64);
        assert!(matches!(check(&input), ProofInputError::InvalidSessionId));
    }

    #[test]
    fn test_accepts_no_session() {
        let mut input = embedding_similarity_fixture();
        input.request.session_id = FieldElement::ZERO;
        check_embedding_similarity_input_validity(&input).expect("no session is valid");
    }

    #[test]
    fn test_rejects_a_tampered_credential() {
        let mut input = embedding_similarity_fixture();
        input.credential_id += 1;
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidCredentialSignature
        ));
    }

    #[test]
    fn test_rejects_an_expired_credential() {
        let mut input = embedding_similarity_fixture();
        input.now = u32::try_from(input.expires_at).unwrap();
        resign(&mut input);
        assert!(matches!(
            check(&input),
            ProofInputError::CredentialExpired { .. }
        ));
    }

    #[test]
    fn test_rejects_a_credential_issued_too_recently() {
        let mut input = embedding_similarity_fixture();
        input.request.genesis_issued_at_min = input.genesis_issued_at + 1;
        assert!(matches!(
            check(&input),
            ProofInputError::CredentialGenesisExpired { .. }
        ));
    }

    #[test]
    fn test_rejects_a_credential_expiring_too_early() {
        let mut input = embedding_similarity_fixture();
        input.request.expires_at_min = input.expires_at;
        assert!(matches!(
            check(&input),
            ProofInputError::CredentialExpired { .. }
        ));
    }

    #[test]
    fn test_rejects_a_billing_nullifier_of_another_world_id() {
        let mut input = embedding_similarity_billed_fixture();
        input.billing_oprf_output[0] = FieldElement::from(1_u64);
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidBillingNullifier
        ));
    }

    #[test]
    fn test_rejects_hashes_json_the_claim_does_not_commit_to() {
        let mut input = embedding_similarity_fixture();
        // Byte 2 is in the first key, away from the thumbnail digest the token signs.
        input.hashes_json[2] ^= 0x01;
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidHashesJsonClaim
        ));
    }

    #[test]
    fn test_rejects_hashes_json_without_a_thumbnail() {
        let mut input = embedding_similarity_fixture();
        let json = String::from_utf8(input.hashes_json).unwrap();
        input.hashes_json = json.replace("thumbnail.png", "thumbnail.jpg").into_bytes();
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidHashesJson {
                reason: "no thumbnail.png entry"
            }
        ));
    }

    #[test]
    fn test_rejects_hashes_json_outside_the_accepted_lengths() {
        let mut input = embedding_similarity_fixture();
        input.hashes_json.resize(MAX_HASHES_JSON_BYTES + 1, b' ');
        assert!(matches!(
            check(&input),
            ProofInputError::InvalidHashesJson {
                reason: "length is outside the accepted range"
            }
        ));
    }
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "embed-embedding-similarity-prover",
    feature = "embed-embedding-similarity-verifier"
))]
mod tests {
    use super::*;

    use crate::{
        artifacts::embedded::EmbeddedZkArtifacts,
        embedding_similarity_fixtures::embedding_similarity_fixture,
    };

    #[test]
    fn test_embedding_similarity_artifacts_bind_public_input_count() {
        let artifacts = EmbeddedZkArtifacts;
        let prover = artifacts
            .embedding_similarity_prover()
            .expect("embedded prover loads");
        let verifier = artifacts
            .embedding_similarity_verifier()
            .expect("embedded verifier loads");

        // 20 public parameters, two of which are public keys.
        assert_eq!(prover.r1cs.num_public_inputs, 22);
        assert_eq!(verifier.r1cs.num_public_inputs, 22);
        assert_eq!(verifier.r1cs.hash(), prover.r1cs.hash());
    }

    #[test]
    #[ignore = "expensive: proves the full circuit; run with --release --include-ignored"]
    fn test_generate_and_verify_embedding_similarity_proof() {
        let input = embedding_similarity_fixture();
        let request = input.request.clone();
        let root = input.inclusion_proof.root;

        let artifacts = EmbeddedZkArtifacts;
        let proof = generate_embedding_similarity_proof(input, &artifacts).unwrap();
        assert_eq!(proof.merkle_root, root);
        verify_embedding_similarity_proof(&proof, &request, &artifacts)
            .expect("embedding similarity proof verifies");

        // Every public input is bound: a different RP or signal fails.
        let mut other_rp = request.clone();
        other_rp.rp_id = FieldElement::from(1_u64);
        let mut other_signal = request.clone();
        other_signal.signal_hash = FieldElement::from(1_u64);
        for tampered in [other_rp, other_signal] {
            let err = verify_embedding_similarity_proof(&proof, &tampered, &artifacts).unwrap_err();
            assert!(matches!(err, ProofError::Verification(_)));
        }

        // So are the values the proof carries: a different root or Verifier key fails.
        let mut other_root = proof.clone();
        other_root.merkle_root = FieldElement::from(1_u64);
        let mut other_verifier = proof.clone();
        other_verifier.flamingo_verifier_key = proof.cred_pk.clone();
        for tampered in [other_root, other_verifier] {
            let err =
                verify_embedding_similarity_proof(&tampered, &request, &artifacts).unwrap_err();
            assert!(matches!(err, ProofError::Verification(_)));
        }
    }

    /// [`check_embedding_similarity_input_validity`] rejects a bad input before proving.
    #[test]
    fn test_generation_rejects_invalid_inputs_before_proving() {
        let mut input = embedding_similarity_fixture();
        input.request.challenge_hash = FieldElement::ZERO;
        let err = generate_embedding_similarity_proof(input, &EmbeddedZkArtifacts).unwrap_err();
        assert!(matches!(
            err,
            ProofError::ProofInputError(ProofInputError::ValueMustNotBeZero {
                name: "challenge_hash"
            })
        ));
    }
}
