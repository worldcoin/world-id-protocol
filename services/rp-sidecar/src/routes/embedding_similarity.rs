//! `POST /v1/embedding-similarity/verify`.

use std::sync::Arc;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use world_id_primitives::{ProofRequest, ProofResponse};
use world_id_rp::embedding_similarity::{FlamingoAttestationVerifier, check_embedding_similarity};

use crate::{
    error::{ApiError, Failure},
    metrics::METRICS_EMBEDDING_SIMILARITY_VERIFICATIONS,
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
/// The caller MUST send the request from its own store, and consume it on `200` so the request
/// accepts at most one proof (WIP-201 §4.7 check 4).
pub(super) async fn verify<A, R>(
    State(state): State<Arc<AppState<A, R>>>,
    body: Result<Json<VerifyRequest>, JsonRejection>,
) -> Response
where
    A: FlamingoAttestationVerifier + Send + Sync + 'static,
    R: Registries,
{
    let result = match body {
        Ok(Json(body)) => verify_proof(&state, body).await,
        Err(rejection) => Err(ApiError::from(rejection)),
    };
    report(result.as_ref().err());
    match result {
        Ok(()) => Json(json!({ "result": "accepted" })).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn verify_proof<A, R>(state: &AppState<A, R>, body: VerifyRequest) -> Result<(), ApiError>
where
    A: FlamingoAttestationVerifier + Send + Sync + 'static,
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

    let permit = Arc::clone(&state.proof_verifications)
        .try_acquire_owned()
        .map_err(|_| ApiError::overloaded())?;
    let artifacts = Arc::clone(&state.artifacts);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        check.verify_proof(artifacts.as_ref())
    })
    .await
    .map_err(|error| ApiError::verification_panicked(&error))??;
    Ok(())
}

/// Counts every verification, and logs those that reached no verdict, since they point at the
/// sidecar or its dependencies. Rejections are only counted: the caller receives their reason.
fn report(error: Option<&ApiError>) {
    let (result, code) = error.map_or(("accepted", "accepted"), |error| {
        (error.result().as_str(), error.code())
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
    match error.result() {
        Failure::Unavailable => {
            tracing::warn!(code, message = error.message(), "no verdict on the proof");
        }
        Failure::Internal => {
            tracing::error!(code, message = error.message(), "proof verification failed");
        }
        Failure::Invalid | Failure::Rejected => {}
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        num::NonZeroUsize,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use alloy::primitives::{Signature, U256};
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header::RETRY_AFTER},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt as _;
    use world_id_primitives::{
        EdDSAPrivateKey, EdDSAPublicKey, EmbeddingSimilarityParams, EmbeddingSimilarityProof,
        EmbeddingSimilarityResponseItem, FieldElement, OprfKeyId, OprfPrefix, ProofRequest,
        ProofResponse, ProofType, RequestItem, RequestVersion, SessionRef, rp::RpId,
    };
    use world_id_proof::artifacts::embedded::EmbeddedZkArtifacts;
    use world_id_rp::embedding_similarity::{
        AatPolicy, EmbeddingSimilarityPolicy, FlamingoAttestationVerifier,
    };

    use crate::{
        registries::{Registries, RegistryError},
        routes::router,
        server::AppState,
    };

    const ENGINE_CONFIG_HASH: u64 = 10;
    const ISSUER_VERSION: u8 = 1;

    /// Accepts an attestation that is the attested key's compressed bytes.
    struct KeyAsAttestation;

    impl FlamingoAttestationVerifier for KeyAsAttestation {
        fn attested_key(&self, attestation: &[u8]) -> Result<EdDSAPublicKey, String> {
            let key: [u8; 32] = attestation
                .try_into()
                .map_err(|_| "not a compressed key".to_owned())?;
            EdDSAPublicKey::from_compressed_bytes(key).map_err(|error| error.to_string())
        }
    }

    /// Registries that answer every check the same way.
    #[derive(Clone, Copy)]
    enum FixedRegistries {
        Trusting,
        Distrusting,
        Unreachable,
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
        async fn answer(self) -> Result<bool, RegistryError> {
            match self {
                Self::Trusting => Ok(true),
                Self::Distrusting => Ok(false),
                Self::Unreachable => Err(unreachable_rpc().await),
            }
        }
    }

    /// The error a registry read returns when its RPC endpoint refuses connections.
    async fn unreachable_rpc() -> RegistryError {
        use alloy::providers::{Provider as _, ProviderBuilder};

        let provider = ProviderBuilder::new()
            .connect_http("http://127.0.0.1:1".parse().unwrap())
            .erased();
        let registries = crate::registries::OnchainRegistries::new(
            provider,
            alloy::primitives::Address::ZERO,
            alloy::primitives::Address::ZERO,
        );
        registries
            .is_valid_root(FieldElement::ZERO)
            .await
            .unwrap_err()
    }

    struct Fixture {
        request: ProofRequest,
        response: ProofResponse,
    }

    /// A Proof of Embedding Similarity request, and a response that passes every check before
    /// the registries but carries no valid proof.
    fn fixture() -> Fixture {
        let now = now_secs();
        let verifier_key = EdDSAPrivateKey::random(&mut rand::thread_rng()).public();
        let action = FieldElement::try_from(
            U256::from(7) | (U256::from(OprfPrefix::EmbeddingSimilarity as u8) << 248),
        )
        .unwrap();
        let request = ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            proof_type: ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
                action,
                challenge_hash: FieldElement::from(0x00c0_ffee_u64),
                aat: None,
            }),
            session_id: SessionRef::None,
            created_at: now,
            expires_at: now + 300,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(alloy::primitives::U160::from(1)),
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
                    cred_pk: EdDSAPrivateKey::random(&mut rand::thread_rng()).public(),
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

    fn app(
        registries: FixedRegistries,
        max_concurrent_verifications: usize,
    ) -> (Router, AppStateProbe) {
        let policy = EmbeddingSimilarityPolicy {
            attestation: KeyAsAttestation,
            engine_config_hashes: HashSet::from([FieldElement::from(ENGINE_CONFIG_HASH)]),
            issuer_version: ISSUER_VERSION,
            aat: AatPolicy::default(),
        };
        let state = AppState::new(
            policy,
            registries,
            Arc::new(EmbeddedZkArtifacts),
            NonZeroUsize::new(max_concurrent_verifications).unwrap(),
        );
        let probe = AppStateProbe {
            proof_verifications: Arc::clone(&state.proof_verifications),
            held: Mutex::new(Vec::new()),
        };
        (router(state, 30, 64 * 1024), probe)
    }

    /// Reaches into the state the router owns, to occupy its verification slots.
    struct AppStateProbe {
        proof_verifications: Arc<tokio::sync::Semaphore>,
        held: Mutex<Vec<tokio::sync::OwnedSemaphorePermit>>,
    }

    impl AppStateProbe {
        fn occupy_every_slot(&self) {
            while let Ok(permit) = Arc::clone(&self.proof_verifications).try_acquire_owned() {
                self.held.lock().unwrap().push(permit);
            }
        }
    }

    async fn post(app: Router, body: Body) -> (StatusCode, Option<String>, Value) {
        let response = app
            .oneshot(
                Request::post("/v1/embedding-similarity/verify")
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .map(|value| value.to_str().unwrap().to_owned());
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, retry_after, serde_json::from_slice(&bytes).unwrap())
    }

    async fn verify(app: Router, fixture: &Fixture) -> (StatusCode, Option<String>, Value) {
        let body = json!({ "request": fixture.request, "response": fixture.response });
        post(app, Body::from(body.to_string())).await
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// `ProveKit` checks a transcript pattern only in debug builds, and panics on a forged proof
    /// that lacks one; release builds reject it.
    #[tokio::test]
    async fn an_invalid_proof_is_not_accepted_and_frees_its_slot() {
        let (app, _probe) = app(FixedRegistries::Trusting, 1);

        let (status, _, body) = verify(app.clone(), &fixture()).await;
        let (_, _, retried) = verify(app, &fixture()).await;

        if cfg!(debug_assertions) {
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(body["code"], "verification_panicked");
        } else {
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(body["result"], "rejected");
            assert_eq!(body["code"], "invalid_proof");
        }
        assert_eq!(retried["code"], body["code"]);
    }

    #[tokio::test]
    async fn an_expired_request_is_rejected() {
        let (app, _probe) = app(FixedRegistries::Trusting, 1);
        let mut fixture = fixture();
        fixture.request.created_at = 1;
        fixture.request.expires_at = 2;

        let (status, _, body) = verify(app, &fixture).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "request_expired");
    }

    #[tokio::test]
    async fn an_untrusted_root_is_rejected() {
        let (app, _probe) = app(FixedRegistries::Distrusting, 1);

        let (status, _, body) = verify(app, &fixture()).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "invalid_root");
    }

    #[tokio::test]
    async fn an_unreachable_registry_is_retryable_not_a_rejection() {
        let (app, _probe) = app(FixedRegistries::Unreachable, 1);

        let (status, retry_after, body) = verify(app, &fixture()).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after.as_deref(), Some("1"));
        assert_eq!(body["result"], "unavailable");
        assert_eq!(body["code"], "root_check_failed");
    }

    #[tokio::test]
    async fn verifications_beyond_capacity_are_shed() {
        let (app, probe) = app(FixedRegistries::Trusting, 1);
        probe.occupy_every_slot();

        let (status, retry_after, body) = verify(app, &fixture()).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after.as_deref(), Some("1"));
        assert_eq!(body["code"], "overloaded");
    }

    #[tokio::test]
    async fn a_request_for_another_proof_type_is_invalid() {
        let (app, _probe) = app(FixedRegistries::Trusting, 1);
        let mut fixture = fixture();
        fixture.request.proof_type = ProofType::Uniqueness {
            action: FieldElement::from(7u64),
        };

        let (status, _, body) = verify(app, &fixture).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["result"], "invalid");
        assert_eq!(body["code"], "not_embedding_similarity");
    }

    #[tokio::test]
    async fn malformed_and_oversized_bodies_are_invalid() {
        let (app, _probe) = app(FixedRegistries::Trusting, 1);

        let (malformed, _, malformed_body) =
            post(app.clone(), Body::from(r#"{"request": {}}"#)).await;
        let (oversized, _, oversized_body) = post(app, Body::from(vec![b' '; 128 * 1024])).await;

        assert_eq!(malformed, StatusCode::BAD_REQUEST);
        assert_eq!(malformed_body["code"], "invalid_body");
        assert_eq!(oversized, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(oversized_body["code"], "body_too_large");
    }
}
