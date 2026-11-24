//! Helpers shared by the sidecar's tests.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::RETRY_AFTER},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use world_id_primitives::{EdDSAPublicKey, ProofRequest, ProofResponse};
use world_id_rp::embedding_similarity::FlamingoAttestationVerifier;

/// Stands in for the Nitro check: the attestation is the attested key's compressed bytes.
pub struct KeyAsAttestation;

impl FlamingoAttestationVerifier for KeyAsAttestation {
    fn attested_key(&self, attestation: &[u8]) -> Result<EdDSAPublicKey, String> {
        let key: [u8; 32] = attestation
            .try_into()
            .map_err(|_| "not a compressed key".to_owned())?;
        EdDSAPublicKey::from_compressed_bytes(key).map_err(|error| error.to_string())
    }
}

/// The sidecar's answer to a verification.
pub struct Answer {
    pub status: StatusCode,
    pub retry_after: Option<String>,
    pub body: Value,
}

/// Posts the verification of `response` to `request` to `app`'s verify route.
pub async fn post_verification(
    app: Router,
    request: &ProofRequest,
    response: &ProofResponse,
) -> Answer {
    post_verification_with_live_capture(app, request, response, None).await
}

/// Like [`post_verification`], with the `live_capture` body field when the request sets
/// `return_live_capture`.
pub async fn post_verification_with_live_capture(
    app: Router,
    request: &ProofRequest,
    response: &ProofResponse,
    live_capture: Option<&[u8]>,
) -> Answer {
    let mut body = json!({ "request": request, "response": response });
    if let Some(image) = live_capture {
        body.as_object_mut().unwrap().insert(
            "live_capture".into(),
            json!(format!("0x{}", hex::encode(image))),
        );
    }
    post_body(app, body.to_string()).await
}

/// Posts `body` to `app`'s verify route.
pub async fn post_body(app: Router, body: impl Into<Body>) -> Answer {
    let response = app
        .oneshot(
            Request::post("/v1/embedding-similarity/verify")
                .header("content-type", "application/json")
                .body(body.into())
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
    Answer {
        status,
        retry_after,
        body: serde_json::from_slice(&bytes).unwrap(),
    }
}
