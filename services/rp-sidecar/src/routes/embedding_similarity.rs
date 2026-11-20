//! `POST /v1/embedding-similarity/verify`.

use std::{sync::Arc, time::Instant};

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tokio::runtime::Handle;
use world_id_primitives::{ProofRequest, ProofResponse};
use world_id_rp::embedding_similarity::{FlamingoAttestationVerifier, check_embedding_similarity};

use crate::{
    error::{ApiError, Code, Failure},
    metrics::{
        METRICS_EMBEDDING_SIMILARITY_PROOF_VERIFICATION_MS,
        METRICS_EMBEDDING_SIMILARITY_VERIFICATIONS,
    },
    registries::Registries,
    server::AppState,
};

/// A verification: the request the RP issued, from the RP's own store, and the response to it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifyRequest {
    request: ProofRequest,
    response: ProofResponse,
}

/// Verifies a Proof of Embedding Similarity under WIP-202 §4.8 and answers `200` only if it is
/// accepted.
///
/// The caller MUST send the request from its own store, and consume the stored request on `200`
/// so that it accepts at most one proof (WIP-201 §4.7 check 4).
pub(super) async fn verify<A, R>(
    State(state): State<Arc<AppState<A, R>>>,
    body: Result<Json<VerifyRequest>, JsonRejection>,
) -> Response
where
    A: FlamingoAttestationVerifier + Send + Sync + 'static,
    R: Registries,
{
    let result = match body {
        Ok(Json(body)) => verify_embedding_similarity(state, body).await,
        Err(rejection) => Err(ApiError::from(rejection)),
    };
    report(result.as_ref().err());
    match result {
        Ok(()) => Json(json!({ "result": "accepted" })).into_response(),
        Err(error) => error.into_response(),
    }
}

/// Runs the whole verification on a blocking thread, in one of the verification slots.
///
/// The Flamingo attestation check and the proof verification are both CPU-bound, so neither runs
/// on the async runtime. A request arriving when every slot is busy is shed before it costs
/// anything. A verification that misses the deadline is answered `503 timeout` and still runs
/// to its end in its slot.
async fn verify_embedding_similarity<A, R>(
    state: Arc<AppState<A, R>>,
    body: VerifyRequest,
) -> Result<(), ApiError>
where
    A: FlamingoAttestationVerifier + Send + Sync + 'static,
    R: Registries,
{
    let slot = Arc::clone(&state.verification_slots)
        .try_acquire_owned()
        .map_err(|_| ApiError::overloaded())?;
    let timeout = state.request_timeout;
    let runtime = Handle::current();
    let verification = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        runtime.block_on(check_and_verify(&state, &body))
    });
    match tokio::time::timeout(timeout, verification).await {
        Err(_elapsed) => Err(ApiError::timeout(timeout)),
        Ok(Err(panic)) => Err(ApiError::verification_panicked(&panic)),
        Ok(Ok(result)) => result,
    }
}

async fn check_and_verify<A, R>(
    state: &AppState<A, R>,
    body: &VerifyRequest,
) -> Result<(), ApiError>
where
    A: FlamingoAttestationVerifier + Sync,
    R: Registries,
{
    let check = check_embedding_similarity(
        &body.request,
        &body.response,
        &state.policy,
        |root| state.registries.is_valid_root(root),
        |key| state.registries.is_trusted_issuer(key),
    )
    .await?;
    let started = Instant::now();
    let verified = check.verify_proof(state.artifacts.as_ref());
    metrics::histogram!(METRICS_EMBEDDING_SIMILARITY_PROOF_VERIFICATION_MS)
        .record(started.elapsed().as_secs_f64() * 1_000.0);
    Ok(verified?)
}

/// Counts every verification, and logs those that reached no verdict because a dependency or
/// the sidecar failed. Rejections and shed requests are only counted: rejections reach the
/// caller with their reason, and logging every shed request would add load when overloaded.
fn report(error: Option<&ApiError>) {
    let (result, code) = error.map_or(("accepted", "accepted"), |error| {
        (error.code().failure().as_str(), error.code().as_str())
    });
    metrics::counter!(
        METRICS_EMBEDDING_SIMILARITY_VERIFICATIONS,
        "result" => result,
        "code" => code,
    )
    .increment(1);

    let Some(error) = error else {
        return;
    };
    let code = error.code();
    match code.failure() {
        Failure::Unavailable if code != Code::Overloaded => {
            tracing::warn!(
                code = code.as_str(),
                message = error.message(),
                "no verdict on the proof"
            );
        }
        Failure::Internal => {
            tracing::error!(
                code = code.as_str(),
                message = error.message(),
                "proof verification failed"
            );
        }
        Failure::Invalid | Failure::Rejected | Failure::Unavailable => {}
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        num::NonZeroUsize,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use alloy::primitives::{Signature, U160, U256};
    use axum::{Router, body::Body, http::StatusCode};
    use serde_json::json;
    use tokio::sync::Semaphore;
    use world_id_primitives::{
        EdDSAPrivateKey, EdDSAPublicKey, EmbeddingSimilarityParams, EmbeddingSimilarityProof,
        EmbeddingSimilarityResponseItem, FieldElement, OprfKeyId, OprfPrefix,
        OprfPrefixedFieldElement as _, ProofRequest, ProofResponse, ProofType, RequestItem,
        RequestVersion, SessionRef, rp::RpId,
    };
    use world_id_proof::artifacts::embedded::EmbeddedZkArtifacts;
    use world_id_rp::embedding_similarity::{AatPolicy, EmbeddingSimilarityPolicy};

    use crate::{
        config::defaults::MAX_BODY_BYTES,
        registries::{Registries, RegistryError},
        routes::router,
        server::AppState,
        test_support::{Answer, KeyAsAttestation, post_verify},
    };

    const ENGINE_CONFIG_HASH: u64 = 10;
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    /// Registries that answer every check the same way.
    enum FixedRegistries {
        Trusting,
        Distrusting,
        Failing,
        /// Answers only once the gate has a permit.
        Stalled(Arc<Semaphore>),
        /// Fails the test if it is asked.
        NeverAsked,
    }

    impl Registries for FixedRegistries {
        async fn is_valid_root(&self, _root: FieldElement) -> Result<bool, RegistryError> {
            self.answer().await
        }

        async fn is_trusted_issuer(&self, _key: EdDSAPublicKey) -> Result<bool, RegistryError> {
            self.answer().await
        }
    }

    impl FixedRegistries {
        async fn answer(&self) -> Result<bool, RegistryError> {
            match self {
                Self::Trusting => Ok(true),
                Self::Distrusting => Ok(false),
                Self::Failing => Err(RegistryError::new(
                    "WorldIDRegistry.isValidRoot",
                    "connection refused".to_owned(),
                )),
                Self::Stalled(gate) => {
                    drop(gate.acquire().await);
                    Ok(true)
                }
                Self::NeverAsked => panic!("the registries were asked"),
            }
        }
    }

    fn state(
        registries: FixedRegistries,
        timeout: Duration,
    ) -> AppState<KeyAsAttestation, FixedRegistries> {
        let policy = EmbeddingSimilarityPolicy {
            attestation: KeyAsAttestation,
            engine_config_hashes: HashSet::from([FieldElement::from(ENGINE_CONFIG_HASH)]),
            issuer_version: 1,
            aat: AatPolicy::default(),
        };
        AppState::new(
            policy,
            registries,
            Arc::new(EmbeddedZkArtifacts),
            NonZeroUsize::MIN,
            timeout,
        )
    }

    fn app(registries: FixedRegistries) -> Router {
        router(state(registries, REQUEST_TIMEOUT), MAX_BODY_BYTES)
    }

    struct Fixture {
        request: ProofRequest,
        response: ProofResponse,
    }

    /// A Proof of Embedding Similarity request, and a response that passes every check before
    /// the registries but carries no valid proof.
    fn fixture() -> Fixture {
        let mut rng = rand::thread_rng();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let verifier_key = EdDSAPrivateKey::random(&mut rng).public();
        let request = ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            proof_type: ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
                action: FieldElement::random_with_prefix(&mut rng, OprfPrefix::EmbeddingSimilarity),
                challenge_hash: FieldElement::from(0x00c0_ffee_u64),
                aat: None,
            }),
            session_id: SessionRef::None,
            created_at: now,
            expires_at: now + 300,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(U160::from(1)),
            signature: Signature::new(U256::from(1), U256::from(1), false),
            nonce: FieldElement::from(1u64),
            requests: vec![RequestItem::embedding_similarity(
                "poh".into(),
                None,
                None,
                None,
            )],
            constraints: None,
        };
        let response = ProofResponse {
            id: "req".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![],
            embedding_similarity: Some(EmbeddingSimilarityResponseItem {
                identifier: "poh".into(),
                proof: EmbeddingSimilarityProof {
                    proof: provekit_common::WhirR1CSProof {
                        narg_string: vec![1, 2, 3],
                        hints: vec![4, 5],
                        #[cfg(debug_assertions)]
                        pattern: vec![],
                    },
                    now: u32::try_from(now).unwrap(),
                    flamingo_verifier_key: verifier_key.clone(),
                    engine_config_hash: FieldElement::from(ENGINE_CONFIG_HASH),
                    aat: None,
                    merkle_root: FieldElement::from(11u64),
                    cred_pk: EdDSAPrivateKey::random(&mut rng).public(),
                },
                signing_key_attestation: verifier_key
                    .to_compressed_bytes()
                    .unwrap()
                    .to_vec()
                    .into(),
            }),
        };
        Fixture { request, response }
    }

    async fn verify(app: Router, fixture: &Fixture) -> Answer {
        let body = json!({ "request": fixture.request, "response": fixture.response });
        post_verify(app, body.to_string()).await
    }

    /// `ProveKit` checks the prover's transcript pattern in debug builds and panics on any proof
    /// that lacks it, as every proof does after serialization; release builds reject the proof.
    #[tokio::test]
    async fn an_invalid_proof_is_not_accepted_and_frees_its_slot() {
        let app = app(FixedRegistries::Trusting);

        let first = verify(app.clone(), &fixture()).await;
        let second = verify(app, &fixture()).await;

        if cfg!(debug_assertions) {
            assert_eq!(first.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(first.body["code"], "verification_panicked");
        } else {
            assert_eq!(first.status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(first.body["result"], "rejected");
            assert_eq!(first.body["code"], "invalid_proof");
        }
        assert_eq!(second.body["code"], first.body["code"]);
    }

    #[tokio::test]
    async fn an_expired_request_is_rejected() {
        let mut fixture = fixture();
        fixture.request.created_at = 1;
        fixture.request.expires_at = 2;

        let answer = verify(app(FixedRegistries::Trusting), &fixture).await;

        assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(answer.body["code"], "request_expired");
    }

    #[tokio::test]
    async fn an_untrusted_root_is_rejected() {
        let answer = verify(app(FixedRegistries::Distrusting), &fixture()).await;

        assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(answer.body["code"], "invalid_root");
    }

    #[tokio::test]
    async fn a_failing_registry_is_retryable_not_a_rejection() {
        let answer = verify(app(FixedRegistries::Failing), &fixture()).await;

        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer.retry_after.as_deref(), Some("1"));
        assert_eq!(answer.body["result"], "unavailable");
        assert_eq!(answer.body["code"], "root_check_failed");
    }

    #[tokio::test]
    async fn a_verification_past_the_deadline_is_retryable() {
        let gate = Arc::new(Semaphore::new(0));
        let state = state(
            FixedRegistries::Stalled(Arc::clone(&gate)),
            Duration::from_millis(50),
        );

        let answer = verify(router(state, MAX_BODY_BYTES), &fixture()).await;
        gate.add_permits(1);

        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer.retry_after.as_deref(), Some("1"));
        assert_eq!(answer.body["code"], "timeout");
    }

    #[tokio::test]
    async fn requests_beyond_capacity_are_shed_before_the_registries_are_asked() {
        let state = state(FixedRegistries::NeverAsked, REQUEST_TIMEOUT);
        let _busy = Arc::clone(&state.verification_slots)
            .try_acquire_owned()
            .unwrap();

        let answer = verify(router(state, MAX_BODY_BYTES), &fixture()).await;

        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer.retry_after.as_deref(), Some("1"));
        assert_eq!(answer.body["code"], "overloaded");
    }

    #[tokio::test]
    async fn a_request_for_another_proof_type_is_invalid() {
        let mut fixture = fixture();
        fixture.request.proof_type = ProofType::Uniqueness {
            action: FieldElement::from(7u64),
        };

        let answer = verify(app(FixedRegistries::Trusting), &fixture).await;

        assert_eq!(answer.status, StatusCode::BAD_REQUEST);
        assert_eq!(answer.body["result"], "invalid");
        assert_eq!(answer.body["code"], "not_embedding_similarity");
    }

    #[tokio::test]
    async fn a_malformed_stored_request_is_invalid_not_a_rejected_proof() {
        let mut fixture = fixture();
        let ProofType::EmbeddingSimilarity(params) = &mut fixture.request.proof_type else {
            unreachable!("the fixture requests a Proof of Embedding Similarity");
        };
        params.challenge_hash = FieldElement::ZERO;

        let answer = verify(app(FixedRegistries::Trusting), &fixture).await;

        assert_eq!(answer.status, StatusCode::BAD_REQUEST);
        assert_eq!(answer.body["code"], "invalid_request");
    }

    #[tokio::test]
    async fn malformed_and_oversized_bodies_are_invalid() {
        let malformed = post_verify(app(FixedRegistries::Trusting), r#"{"request": {}}"#).await;
        let oversized = post_verify(
            app(FixedRegistries::Trusting),
            Body::from(vec![b' '; MAX_BODY_BYTES.get() + 1]),
        )
        .await;

        assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
        assert_eq!(malformed.body["code"], "invalid_body");
        assert_eq!(oversized.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(oversized.body["code"], "body_too_large");
    }
}
