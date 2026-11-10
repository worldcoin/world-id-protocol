//! RP verification of the WIP-202 Proof of Embedding Similarity (§4.8).
//!
//! [`verify_embedding_similarity`] checks a [`ProofResponse`] against the RP's own
//! [`ProofRequest`] and [`EmbeddingSimilarityPolicy`]: §4.8 items 2–7 first, then the proof
//! (item 1), as the spec requires.
//!
//! The RP remains responsible for the request itself: it MUST be the RP's own, and its `nonce`
//! one the RP issued and has not seen used before (WIP-201 §4.7 check 4). The challenge image
//! behind `challenge_hash` MUST be one the RP checked against the party it interacts with.

use std::{
    collections::HashSet,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use eddsa_babyjubjub::EdDSAPublicKey;
use world_id_flamingo::{MAX_ATTESTATION_AGE, ReleaseManifest, engine_config_hash};
use world_id_primitives::{
    FieldElement, ProofRequest, ProofResponse, ValidationError,
    authenticator_assertion::AatPublicValues,
};
use world_id_proof::{
    ProofError, artifacts::ZkArtifactSource, circuit_inputs::EmbeddingSimilarityRequestInputs,
    embedding_similarity_proof::verify_embedding_similarity_proof,
};

/// How far the proof's `now` may be from the RP's clock, in seconds (WIP-202 §4.8 item 3).
pub const MAX_CLOCK_SKEW: u64 = 300;

/// Checks a Flamingo Verifier's `signing_key_attestation` (WIP-201 §4.7 check 1).
pub trait FlamingoAttestationVerifier {
    /// Verifies `attestation` and returns the signing key it attests.
    ///
    /// # Errors
    /// A description of why the attestation is not accepted.
    fn attested_key(&self, attestation: &[u8]) -> Result<EdDSAPublicKey, String>;
}

/// The AWS Nitro check: the certificate chain to the AWS Nitro Root G1, non-debug PCR0–2 the
/// RP accepts, and the document's age. Build it with the RP's accepted PCRs and a `max_age` of
/// at most [`MAX_ATTESTATION_AGE`], e.g. [`nitro_attestation_verifier`].
impl FlamingoAttestationVerifier for pontifex::attestation::Verifier {
    fn attested_key(&self, attestation: &[u8]) -> Result<EdDSAPublicKey, String> {
        let verified = self
            .verify_attestation_document(attestation)
            .map_err(|err| err.to_string())?;
        let key: [u8; 32] = verified
            .document()
            .public_key
            .as_ref()
            .ok_or("the attestation attests no public key")?
            .as_slice()
            .try_into()
            .map_err(|_| "the attested public key is not a compressed EdDSA key")?;
        EdDSAPublicKey::from_compressed_bytes(key)
            .map_err(|_| "the attested public key is not a valid EdDSA key".to_string())
    }
}

/// A Nitro attestation verifier accepting `pcrs`, with WIP-201's [`MAX_ATTESTATION_AGE`].
///
/// pontifex checks the document's age against the system clock, as [`verify_embedding_similarity`]
/// does its own time checks.
#[must_use]
pub fn nitro_attestation_verifier(
    pcrs: Vec<pontifex::attestation::PcrConfig>,
) -> pontifex::attestation::Verifier {
    pontifex::attestation::Verifier::new(pcrs, std::time::Duration::from_secs(MAX_ATTESTATION_AGE))
}

/// The AAT flags an RP allowlists (WIP-106 §4 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AatFlags {
    /// The platform.
    pub platform: u8,
    /// The security level.
    pub sec_level: u8,
    /// The security metadata.
    pub sec_meta: u8,
    /// The Authenticator metadata.
    pub authenticator_meta: u8,
}

impl From<&AatPublicValues> for AatFlags {
    fn from(aat: &AatPublicValues) -> Self {
        Self {
            platform: aat.platform,
            sec_level: aat.sec_level,
            sec_meta: aat.sec_meta,
            authenticator_meta: aat.authenticator_meta,
        }
    }
}

/// The RP's policy for the AAT values a proof reveals (WIP-202 §4.8 item 7).
#[derive(Debug, Clone, Default)]
pub struct AatPolicy {
    /// Whether proofs without an AAT are rejected.
    pub required: bool,
    /// The WIP-106 hashes of the trust anchor keys the RP accepts: keys of allowlisted
    /// Authenticator Providers that are active or retired, never revoked.
    pub trust_anchor_key_hashes: HashSet<FieldElement>,
    /// The flag combinations the RP accepts.
    pub accepted_flags: HashSet<AatFlags>,
}

/// What an RP accepts in a Proof of Embedding Similarity, beyond its own request.
#[derive(Debug, Clone)]
pub struct EmbeddingSimilarityPolicy<A> {
    /// Checks the Flamingo Verifier's attestation, e.g. [`nitro_attestation_verifier`].
    pub attestation: A,
    /// The Engine configurations the RP accepts (WIP-201 §4.7 check 6), e.g. from
    /// [`accepted_engine_configs`].
    pub engine_config_hashes: HashSet<FieldElement>,
    /// The PoH Credential's `issuer_version` the RP verifies against.
    pub issuer_version: u8,
    /// The AAT policy.
    pub aat: AatPolicy,
}

/// The `engine_config_hash`es of `pipelines`, given as `(pipeline_id, match_strictness)`, in
/// every manifest at or above `min_version` that defines them.
///
/// Pass only manifests verified under an active key of their `iss`, e.g.
/// [`EngineProviderMetadata::verified_manifests`](world_id_flamingo::EngineProviderMetadata::verified_manifests),
/// and one `min_version` per `iss` (WIP-201 §4.7 check 6).
#[must_use]
pub fn accepted_engine_configs(
    manifests: &[ReleaseManifest],
    min_version: u64,
    pipelines: &[(u16, u8)],
) -> HashSet<FieldElement> {
    manifests
        .iter()
        .filter(|manifest| manifest.payload().version >= min_version)
        .flat_map(|manifest| {
            pipelines
                .iter()
                .filter(|(pipeline_id, match_strictness)| {
                    manifest.pipeline(*pipeline_id).is_some()
                        && manifest.has_match_strictness(*match_strictness)
                })
                .map(|(pipeline_id, match_strictness)| {
                    engine_config_hash(&manifest.release_hash(), *pipeline_id, *match_strictness)
                })
        })
        .collect()
}

/// Why a Proof of Embedding Similarity was rejected.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddingSimilarityVerificationError {
    /// The request is not a Proof of Embedding Similarity request.
    #[error("the request is not an embedding_similarity request")]
    NotEmbeddingSimilarity,
    /// The response does not answer the request.
    #[error(transparent)]
    Response(#[from] ValidationError),
    /// The system clock is before the Unix epoch.
    #[error("the system clock is before the Unix epoch: {0}")]
    Clock(#[from] SystemTimeError),
    /// The request expired before verification.
    #[error("the request expired at {expires_at}")]
    RequestExpired {
        /// The request's `expires_at`.
        expires_at: u64,
    },
    /// The Flamingo Verifier's attestation is not accepted.
    #[error("the Flamingo Verifier attestation is not accepted: {0}")]
    Attestation(String),
    /// The attestation attests another key than the one that signed the token.
    #[error("the attestation does not attest the proof's flamingo_verifier_key")]
    AttestedKeyMismatch,
    /// The Engine configuration is not one the RP accepts.
    #[error("engine_config_hash {0} is not accepted")]
    EngineNotAccepted(FieldElement),
    /// The proof's time is not within [`MAX_CLOCK_SKEW`] of the RP's clock.
    #[error("the proof's time {proof_now} is not within {MAX_CLOCK_SKEW}s of {now}")]
    Stale {
        /// The RP's time.
        now: u64,
        /// The proof's `now`.
        proof_now: u32,
    },
    /// The root check itself failed, e.g. the registry was unreachable.
    #[error("could not check merkle_root: {0}")]
    RootCheck(Box<dyn std::error::Error + Send + Sync>),
    /// The root is not a valid, unexpired root of the `WorldIDRegistry`.
    #[error("merkle_root {0} is not a valid root")]
    InvalidRoot(FieldElement),
    /// The Issuer key check itself failed, e.g. the registry was unreachable.
    #[error("could not check cred_pk: {0}")]
    IssuerCheck(Box<dyn std::error::Error + Send + Sync>),
    /// The Issuer key is not one the RP trusts.
    #[error("cred_pk is not a trusted PoH Issuer key")]
    UntrustedIssuerKey,
    /// The RP requires an AAT and the proof carries none.
    #[error("the proof carries no AAT")]
    AatRequired,
    /// An AAT value is outside the RP's policy.
    #[error("the AAT's {0} is not accepted")]
    AatNotAccepted(&'static str),
    /// The proof does not verify.
    #[error(transparent)]
    Proof(#[from] ProofError),
}

/// Verifies a Proof of Embedding Similarity under WIP-202 §4.8.
///
/// Time checks use the system clock.
///
/// `is_valid_root` checks Root Freshness (WIP-202 §4.7) at verification time, e.g. through
/// `WorldIDRegistry.isValidRoot` or a cache bounded by the root's expiration. An error rejects the
/// proof, as an invalid root does.
///
/// `is_trusted_issuer` checks `cred_pk` is the PoH Issuer's current key, e.g. against
/// `CredentialSchemaIssuerRegistry.issuerSchemaIdToPubkey(POH_ISSUER_SCHEMA_ID)` as
/// `WorldIDVerifier` does. An error rejects the proof.
///
/// # Errors
/// The first failing check, see [`EmbeddingSimilarityVerificationError`].
pub async fn verify_embedding_similarity<A, F, Fut, E, G, GFut, GE>(
    request: &ProofRequest,
    response: &ProofResponse,
    policy: &EmbeddingSimilarityPolicy<A>,
    is_valid_root: F,
    is_trusted_issuer: G,
    artifacts: &dyn ZkArtifactSource,
) -> Result<(), EmbeddingSimilarityVerificationError>
where
    A: FlamingoAttestationVerifier + Sync,
    F: FnOnce(FieldElement) -> Fut + Send,
    Fut: Future<Output = Result<bool, E>> + Send,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
    G: FnOnce(EdDSAPublicKey) -> GFut + Send,
    GFut: Future<Output = Result<bool, GE>> + Send,
    GE: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use EmbeddingSimilarityVerificationError as Error;

    if !request.proof_type.is_embedding_similarity() {
        return Err(Error::NotEmbeddingSimilarity);
    }
    request.validate_response(response)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    check_unexpired(request.expires_at, now)?;
    // `validate_response` guarantees the item for the request's single item.
    let item = response.embedding_similarity.as_ref().ok_or_else(|| {
        ValidationError::MissingCredential(request.requests[0].identifier.clone())
    })?;
    let proof = &item.proof;

    // 2. The Flamingo Token values: WIP-201 checks 1, 4 (through 3 and 5), 5 (through 7) and 6.
    let attested = policy
        .attestation
        .attested_key(&item.signing_key_attestation)
        .map_err(Error::Attestation)?;
    if attested.pk != proof.flamingo_verifier_key.pk {
        return Err(Error::AttestedKeyMismatch);
    }
    if !policy
        .engine_config_hashes
        .contains(&proof.engine_config_hash)
    {
        return Err(Error::EngineNotAccepted(proof.engine_config_hash));
    }

    // 3. The proof is recent.
    check_recent(proof.now, now)?;

    // 4. The World ID and the Credential are trusted.
    if !is_valid_root(proof.merkle_root)
        .await
        .map_err(|err| Error::RootCheck(err.into()))?
    {
        return Err(Error::InvalidRoot(proof.merkle_root));
    }
    if !is_trusted_issuer(proof.cred_pk.clone())
        .await
        .map_err(|err| Error::IssuerCheck(err.into()))?
    {
        return Err(Error::UntrustedIssuerKey);
    }

    // 7. The AAT values are within the RP's policy.
    check_aat(proof.aat.as_ref(), &policy.aat)?;

    // 5 and 6. The request matches: every public input the RP chooses comes from its own request.
    let public = EmbeddingSimilarityRequestInputs::from_request(request, policy.issuer_version)
        .map_err(ProofError::from)?;

    // 1. The proof verifies.
    verify_embedding_similarity_proof(proof, &public, artifacts)?;
    Ok(())
}

const fn check_unexpired(
    expires_at: u64,
    now: u64,
) -> Result<(), EmbeddingSimilarityVerificationError> {
    if now > expires_at {
        return Err(EmbeddingSimilarityVerificationError::RequestExpired { expires_at });
    }
    Ok(())
}

fn check_recent(proof_now: u32, now: u64) -> Result<(), EmbeddingSimilarityVerificationError> {
    if now.abs_diff(u64::from(proof_now)) > MAX_CLOCK_SKEW {
        return Err(EmbeddingSimilarityVerificationError::Stale { now, proof_now });
    }
    Ok(())
}

fn check_aat(
    aat: Option<&AatPublicValues>,
    policy: &AatPolicy,
) -> Result<(), EmbeddingSimilarityVerificationError> {
    use EmbeddingSimilarityVerificationError as Error;
    let Some(aat) = aat else {
        return if policy.required {
            Err(Error::AatRequired)
        } else {
            Ok(())
        };
    };
    if !policy
        .trust_anchor_key_hashes
        .contains(&aat.trust_anchor_key_hash)
    {
        return Err(Error::AatNotAccepted("trust_anchor_key_hash"));
    }
    if !policy.accepted_flags.contains(&AatFlags::from(aat)) {
        return Err(Error::AatNotAccepted("flags"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use world_id_flamingo::{
        ResponseSlots,
        release_manifest::{Input, ManifestPayload, Pipeline},
    };

    use super::*;

    /// A manifest of `version` defining pipelines 1 and 2 at strictness levels 1 and 2. The
    /// signature is not checked by [`ReleaseManifest::from_jws`].
    fn manifest(version: u64) -> ReleaseManifest {
        let pipeline = |pipeline_id| Pipeline {
            pipeline_id,
            inputs: vec![Input {
                role: "live_frame".into(),
                media_types: vec!["image/jpeg".into()],
            }],
            response_slots: ResponseSlots(vec![500, 1587]),
        };
        let payload = ManifestPayload {
            iss: "https://engines.example.com".into(),
            engine_hash: [version as u8; 48],
            version,
            match_strictness_levels: vec![1, 2],
            pipelines: vec![pipeline(1), pipeline(2)],
        };
        let header = r#"{"alg":"ES256","kid":"release-1","typ":"world-id-engine-manifest"}"#;
        let jws = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap()),
            URL_SAFE_NO_PAD.encode([0u8; 64]),
        );
        ReleaseManifest::from_jws(&jws).unwrap()
    }

    #[test]
    fn engine_configs_come_from_accepted_releases_and_pipelines() {
        let (old, new) = (manifest(1), manifest(2));
        let accepted =
            accepted_engine_configs(&[old.clone(), new.clone()], 2, &[(1, 2), (3, 2), (2, 9)]);
        // Only the release at or above the minimum, and only the pipeline and level it defines.
        assert_eq!(
            accepted,
            HashSet::from([engine_config_hash(&new.release_hash(), 1, 2)])
        );
        assert!(!accepted.contains(&engine_config_hash(&old.release_hash(), 1, 2)));
    }

    #[test]
    fn requests_expire_after_expires_at() {
        assert!(check_unexpired(100, 100).is_ok());
        assert!(matches!(
            check_unexpired(100, 101),
            Err(EmbeddingSimilarityVerificationError::RequestExpired { expires_at: 100 })
        ));
    }

    #[test]
    fn proofs_must_be_within_the_clock_skew() {
        let proof_now = 1_000_000;
        let now = u64::from(proof_now);
        assert!(check_recent(proof_now, now - MAX_CLOCK_SKEW).is_ok());
        assert!(check_recent(proof_now, now + MAX_CLOCK_SKEW).is_ok());
        for now in [now - MAX_CLOCK_SKEW - 1, now + MAX_CLOCK_SKEW + 1] {
            assert!(matches!(
                check_recent(proof_now, now),
                Err(EmbeddingSimilarityVerificationError::Stale { .. })
            ));
        }
    }

    fn aat() -> AatPublicValues {
        AatPublicValues {
            trust_anchor_key_hash: FieldElement::from(7u64),
            platform: 1,
            sec_level: 2,
            sec_meta: 3,
            authenticator_meta: 4,
        }
    }

    fn accepting(aat: &AatPublicValues) -> AatPolicy {
        AatPolicy {
            required: false,
            trust_anchor_key_hashes: HashSet::from([aat.trust_anchor_key_hash]),
            accepted_flags: HashSet::from([AatFlags::from(aat)]),
        }
    }

    #[test]
    fn proofs_without_an_aat_pass_unless_one_is_required() {
        let mut policy = AatPolicy::default();
        assert!(check_aat(None, &policy).is_ok());
        policy.required = true;
        assert!(matches!(
            check_aat(None, &policy),
            Err(EmbeddingSimilarityVerificationError::AatRequired)
        ));
    }

    #[test]
    fn an_aat_must_match_the_allowlists() {
        let aat = aat();
        let policy = accepting(&aat);
        assert!(check_aat(Some(&aat), &policy).is_ok());

        let other_anchor = AatPublicValues {
            trust_anchor_key_hash: FieldElement::from(8u64),
            ..aat
        };
        assert!(matches!(
            check_aat(Some(&other_anchor), &policy),
            Err(EmbeddingSimilarityVerificationError::AatNotAccepted(
                "trust_anchor_key_hash"
            ))
        ));
        let other_flags = AatPublicValues {
            sec_level: 9,
            ..aat
        };
        assert!(matches!(
            check_aat(Some(&other_flags), &policy),
            Err(EmbeddingSimilarityVerificationError::AatNotAccepted(
                "flags"
            ))
        ));
    }
}
