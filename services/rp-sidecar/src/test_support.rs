//! Helpers shared by the sidecar's tests.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::RETRY_AFTER},
};
use serde_json::Value;
use tower::ServiceExt as _;
use world_id_primitives::EdDSAPublicKey;
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

/// Posts `body` to `app`'s verify route.
pub async fn post_verify(app: Router, body: impl Into<Body>) -> Answer {
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
