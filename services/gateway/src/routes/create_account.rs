//! Create account handler.

use crate::{
    error::GatewayErrorResponse, request::submit_create_account, routes::middleware::RequestId,
    types::AppState,
};
use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, HeaderName},
};
use tracing::instrument;
use world_id_primitives::api_types::{CreateAccountRequest, GatewayStatusResponse};

pub(super) const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// POST /create-account
///
/// Create a new World ID account.
#[instrument(name = "create_account", skip(state, payload), fields(request_id = %id))]
pub(crate) async fn create_account(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    headers: HeaderMap,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    let key = idempotency_key(&headers)?;
    submit_create_account(id, payload, &state.ctx, key)
        .await
        .map(Json)
}

fn idempotency_key(headers: &HeaderMap) -> Result<Option<&[u8]>, GatewayErrorResponse> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let key = value.as_bytes();
    if values.next().is_some()
        || !(1..=128).contains(&key.len())
        || key
            .iter()
            .any(|byte| !byte.is_ascii_graphic() || *byte == b',')
    {
        return Err(GatewayErrorResponse::bad_request_message(
            "Idempotency-Key must be a single value of 1–128 visible ASCII characters without commas.".to_owned(),
        ));
    }
    Ok(Some(key))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn accepts_a_single_opaque_key_or_no_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(idempotency_key(&headers).unwrap(), None);
        headers.insert(IDEMPOTENCY_KEY, HeaderValue::from_static("opaque-key"));
        assert_eq!(
            idempotency_key(&headers).unwrap(),
            Some(b"opaque-key".as_slice())
        );
        headers.append(IDEMPOTENCY_KEY, HeaderValue::from_static("opaque-key"));
        assert!(idempotency_key(&headers).is_err());
    }

    #[test]
    fn rejects_invalid_key_values() {
        for key in [
            b"".as_slice(),
            b"first,second",
            b"two words",
            &[0xff],
            &[b'x'; 129],
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(IDEMPOTENCY_KEY, HeaderValue::from_bytes(key).unwrap());
            assert!(idempotency_key(&headers).is_err());
        }
    }
}
