//! A real Proof of Embedding Similarity, verified through the HTTP API.
//!
//! Needs Docker, and anvil and forge on `PATH`, for the WIP-202 fixture.

use std::{
    future::{self, Future},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::primitives::Bytes;
use axum::http::StatusCode;
use world_id_core::FlamingoResult;
use world_id_flamingo::{FlamingoClaims, FlamingoToken, engine_config_hash};
use world_id_primitives::{
    EdDSAPrivateKey, EdDSAPublicKey, FieldElement, ProofRequest, ProofResponse,
};
use world_id_proof::{
    artifacts::{ZkArtifactSource, ZkArtifactSourceExt as _, embedded::EmbeddedZkArtifacts},
    embedding_similarity_proof::{COMPARE_SOURCES, flamingo_nonce},
};
use world_id_test_utils::embedding_similarity::{EmbeddingSimilarityFixture, image_hash};

use crate::{
    config::defaults::{MAX_BODY_BYTES, REQUEST_TIMEOUT_SECS},
    registries::{Registries, RegistryError},
    routes::router,
    server::AppState,
    test_support::{Answer, KeyAsAttestation, post_verification},
};

/// Trusts the fixture's root, which only its indexer stub serves, and its Issuer key.
struct FixtureRegistries {
    merkle_root: FieldElement,
    issuer_key: EdDSAPublicKey,
}

impl Registries for FixtureRegistries {
    fn is_valid_root(
        &self,
        root: FieldElement,
    ) -> impl Future<Output = Result<bool, RegistryError>> + Send {
        future::ready(Ok(root == self.merkle_root))
    }

    fn is_trusted_issuer(
        &self,
        key: EdDSAPublicKey,
    ) -> impl Future<Output = Result<bool, RegistryError>> + Send {
        future::ready(Ok(key.pk == self.issuer_key.pk))
    }
}

/// A release build verifies the proof through the API. A debug build cannot, as the README
/// explains, so it checks every step up to the proof verification instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_proof_verifies_through_the_api() -> eyre::Result<()> {
    let artifacts: Arc<dyn ZkArtifactSource> = Arc::new(EmbeddedZkArtifacts.cached());
    let fixture = Box::pin(EmbeddingSimilarityFixture::spawn(Arc::clone(&artifacts))).await?;
    let flamingo = flamingo_result(
        &fixture.proof_request,
        &fixture.credential_image,
        image_hash(&fixture.challenge),
    )?;
    let response = fixture.prove(&flamingo, None).await?;
    let registries = FixtureRegistries {
        merkle_root: fixture.merkle_root,
        issuer_key: fixture.issuer_key.clone(),
    };
    let state = AppState::new(
        fixture.policy(KeyAsAttestation, [engine_config()].into()),
        registries,
        artifacts,
        NonZeroUsize::MIN,
        Duration::from_secs(REQUEST_TIMEOUT_SECS.get()),
    );
    let app = router(state, MAX_BODY_BYTES);

    let answer = post_verification(app.clone(), &fixture.proof_request, &response).await;

    #[cfg(debug_assertions)]
    check_in_debug_build(&answer, &fixture, &response).await?;
    #[cfg(not(debug_assertions))]
    check_in_release_build(&answer, app, &fixture, &response).await;
    Ok(())
}

/// The proof is accepted for its own request, and rejected for another challenge.
#[cfg(not(debug_assertions))]
async fn check_in_release_build(
    answer: &Answer,
    app: axum::Router,
    fixture: &EmbeddingSimilarityFixture,
    response: &ProofResponse,
) {
    use world_id_primitives::ProofType;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.body["result"], "accepted");

    let mut other_challenge = fixture.proof_request.clone();
    let ProofType::EmbeddingSimilarity(params) = &mut other_challenge.proof_type else {
        unreachable!("the fixture requests a Proof of Embedding Similarity");
    };
    params.challenge_hash = image_hash(b"another frame");
    let answer = post_verification(app, &other_challenge, response).await;
    assert_eq!(
        answer.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        answer.body
    );
    assert_eq!(answer.body["code"], "invalid_proof");
}

/// The API fails only at the verifier's check of the transcript pattern, which serialization
/// drops, and the request and the proof verify after a JSON round trip once the pattern is back.
#[cfg(debug_assertions)]
async fn check_in_debug_build(
    answer: &Answer,
    fixture: &EmbeddingSimilarityFixture,
    response: &ProofResponse,
) -> eyre::Result<()> {
    assert_eq!(
        answer.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        answer.body
    );
    assert_eq!(answer.body["code"], "verification_panicked");
    let message = answer.body["message"].as_str().unwrap_or_default();
    assert!(message.contains("pattern"), "{message}");

    let request: ProofRequest =
        serde_json::from_str(&serde_json::to_string(&fixture.proof_request)?)?;
    let mut decoded: ProofResponse = serde_json::from_str(&serde_json::to_string(response)?)?;
    let sent = response.embedding_similarity.as_ref().expect("a proof");
    let received = decoded.embedding_similarity.as_mut().expect("a proof");
    received
        .proof
        .proof
        .pattern
        .clone_from(&sent.proof.proof.pattern);
    let policy = fixture.policy(KeyAsAttestation, [engine_config()].into());
    fixture.verify(&request, &decoded, &policy).await?;
    Ok(())
}

/// The Engine configuration the fixture's Flamingo result names and the policy accepts.
fn engine_config() -> FieldElement {
    engine_config_hash(&[0xE7; 32], 1, 2)
}

/// A Flamingo Verifier's unbilled result for `proof_request`, comparing the thumbnail, a live
/// capture and the challenge under the WIP-202 entry layout (§4.3).
fn flamingo_result(
    proof_request: &ProofRequest,
    thumbnail: &[u8],
    challenge_hash: FieldElement,
) -> eyre::Result<FlamingoResult> {
    let verifier_sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let nonce_salt = FieldElement::random(&mut rand::thread_rng());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = FlamingoClaims {
        now: u32::try_from(now)?,
        compared_entry_hashes: [
            image_hash(thumbnail),
            image_hash(b"live capture"),
            challenge_hash,
            FieldElement::ZERO,
        ],
        aud: proof_request.rp_id.into(),
        nonce: flamingo_nonce(proof_request.nonce, nonce_salt),
        aat: None,
        compare_sources: COMPARE_SOURCES,
        engine_config_hash: engine_config(),
        billing_nullifier: FieldElement::ZERO,
    };
    let token = FlamingoToken::sign(claims, &verifier_sk)?.to_cwt()?;
    Ok(FlamingoResult {
        token: FlamingoToken::from_cwt(&token)?,
        verifier_key: verifier_sk.public(),
        signing_key_attestation: Bytes::from(verifier_sk.public().to_compressed_bytes()?.to_vec()),
        nonce_salt,
    })
}
