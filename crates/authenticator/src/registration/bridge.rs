//! A client for the message-bridge that carries registration messages (WIP-110).
//!
//! The bridge keys a request and its response by the same [`RequestId`]. Reading either one is
//! single-use, so this client never retries those reads: a retry after a lost reply would consume
//! the message a second time. Writes are retried with bounded exponential backoff and jitter.

use std::time::Duration;

use backon::{ExponentialBuilder, Retryable as _};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};

use super::{BridgeDomain, EncryptedPayload, RequestId};
use crate::service_client::default_http_client;

/// How many times a bridge write is retried after a server error or a transport failure.
const MAX_WRITE_RETRIES: usize = 3;

/// A client for one bridge deployment.
///
/// Native clients bound every request with the same connect and request timeouts as gateway and
/// indexer requests.
#[derive(Clone, Debug)]
pub struct BridgeClient {
    http: reqwest::Client,
    base_url: Url,
}

/// The outcome of [`BridgeClient::publish_request`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The request was stored.
    Published,
    /// A request with this id already exists, e.g. stored by an attempt whose reply was lost.
    AlreadyPublished,
}

/// The state of a response on the bridge, as seen by [`BridgeClient::fetch_response`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseState {
    /// The request has not been read yet.
    Initialized,
    /// The request was read; the response has not arrived yet.
    Retrieved,
    /// The response, which this call consumed.
    Completed(EncryptedPayload),
    /// The session expired, or its response was already consumed.
    NotFound,
}

/// The outcome of [`BridgeClient::put_response`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The response was stored.
    Delivered,
    /// A retry was rejected after an earlier attempt failed in transit. The bridge forgets the
    /// session once it stores a response, so the earlier attempt may have been delivered.
    PossiblyDelivered,
    /// The bridge rejected the response because the session expired or already has a response.
    Rejected,
}

/// Errors from talking to the bridge.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// The request could not be sent or its response could not be read, e.g. on a timeout.
    #[error("bridge request failed: {0}")]
    Transport(#[from] reqwest::Error),
    /// The bridge answered with a status this operation does not expect.
    #[error("bridge returned unexpected status {status}")]
    UnexpectedStatus {
        /// The HTTP status code.
        status: StatusCode,
    },
    /// The bridge URL could not be built from the configured base URL.
    #[error("invalid bridge URL: {0}")]
    InvalidUrl(String),
}

impl BridgeError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::UnexpectedStatus { status } => status.is_server_error(),
            Self::InvalidUrl(_) => false,
        }
    }
}

#[derive(Serialize)]
struct PublishRequestBody<'a> {
    request_id: String,
    iv: &'a str,
    payload: &'a str,
}

#[derive(Deserialize)]
struct ResponseBody {
    status: WireStatus,
    response: Option<EncryptedPayload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireStatus {
    Initialized,
    Retrieved,
    Completed,
}

impl BridgeClient {
    /// Creates a client for the bridge at `base_url`, e.g. `https://bridge.example.org`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidUrl`] if `base_url` cannot be a base for the bridge routes.
    pub fn new(base_url: Url) -> Result<Self, BridgeError> {
        if base_url.cannot_be_a_base() {
            return Err(BridgeError::InvalidUrl(base_url.to_string()));
        }
        Ok(Self {
            http: default_http_client(),
            base_url,
        })
    }

    /// Creates a client for the bridge at `https://{domain}`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidUrl`] if the domain does not form a valid URL.
    pub fn for_domain(domain: &BridgeDomain) -> Result<Self, BridgeError> {
        let url = Url::parse(&format!("https://{domain}"))
            .map_err(|e| BridgeError::InvalidUrl(e.to_string()))?;
        Self::new(url)
    }

    /// Stores the encrypted request under `request_id` (`POST /request`).
    ///
    /// Retried on server errors and transport failures. A retry of a request that the bridge
    /// stored before the reply was lost yields [`PublishOutcome::AlreadyPublished`].
    ///
    /// # Errors
    ///
    /// Returns an error on other statuses, or once retries are exhausted.
    pub async fn publish_request(
        &self,
        request_id: &RequestId,
        request: &EncryptedPayload,
    ) -> Result<PublishOutcome, BridgeError> {
        let url = self.url(&["request"])?;
        let body = PublishRequestBody {
            request_id: request_id.to_string(),
            iv: &request.iv,
            payload: &request.payload,
        };
        let send = || async {
            let response = self.http.post(url.clone()).json(&body).send().await?;
            match response.status() {
                StatusCode::OK | StatusCode::CREATED => Ok(PublishOutcome::Published),
                StatusCode::CONFLICT => Ok(PublishOutcome::AlreadyPublished),
                status => Err(BridgeError::UnexpectedStatus { status }),
            }
        };
        send.retry(write_backoff())
            .when(BridgeError::is_retryable)
            .await
    }

    /// Takes the encrypted request stored under `request_id` (`GET /request/:id`).
    ///
    /// The read is single-use and is not retried. Returns `None` if the request expired or was
    /// already taken.
    ///
    /// # Errors
    ///
    /// Returns an error on a transport failure or an unexpected status. A transport failure may
    /// have consumed the request.
    pub async fn take_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<EncryptedPayload>, BridgeError> {
        let response = self
            .http
            .get(self.url(&["request", &request_id.to_string()])?)
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => Ok(Some(response.json().await?)),
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(BridgeError::UnexpectedStatus { status }),
        }
    }

    /// Reads the state of the response to `request_id` (`GET /response/:id`), consuming the
    /// response if it has arrived.
    ///
    /// The read is not retried, since a completed response is single-use.
    ///
    /// # Errors
    ///
    /// Returns an error on a transport failure or an unexpected status. A transport failure may
    /// have consumed a completed response.
    pub async fn fetch_response(
        &self,
        request_id: &RequestId,
    ) -> Result<ResponseState, BridgeError> {
        let response = self
            .http
            .get(self.url(&["response", &request_id.to_string()])?)
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Ok(ResponseState::NotFound),
            status => return Err(BridgeError::UnexpectedStatus { status }),
        }
        let body: ResponseBody = response.json().await?;
        Ok(match (body.status, body.response) {
            (WireStatus::Completed, Some(payload)) => ResponseState::Completed(payload),
            (WireStatus::Initialized, _) => ResponseState::Initialized,
            (WireStatus::Retrieved, _) => ResponseState::Retrieved,
            (WireStatus::Completed, None) => ResponseState::NotFound,
        })
    }

    /// Stores the encrypted response to `request_id` (`PUT /response/:id`).
    ///
    /// Retried on server errors and transport failures.
    ///
    /// # Errors
    ///
    /// Returns an error on other unexpected statuses, or once retries are exhausted.
    pub async fn put_response(
        &self,
        request_id: &RequestId,
        response: &EncryptedPayload,
    ) -> Result<DeliveryOutcome, BridgeError> {
        let url = self.url(&["response", &request_id.to_string()])?;
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let send = || async {
            let is_retry = attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed) > 0;
            let reply = self.http.put(url.clone()).json(response).send().await?;
            match reply.status() {
                StatusCode::CREATED | StatusCode::OK => Ok(DeliveryOutcome::Delivered),
                StatusCode::BAD_REQUEST | StatusCode::CONFLICT if is_retry => {
                    Ok(DeliveryOutcome::PossiblyDelivered)
                }
                StatusCode::BAD_REQUEST | StatusCode::CONFLICT => Ok(DeliveryOutcome::Rejected),
                status => Err(BridgeError::UnexpectedStatus { status }),
            }
        };
        send.retry(write_backoff())
            .when(BridgeError::is_retryable)
            .await
    }

    fn url(&self, segments: &[&str]) -> Result<Url, BridgeError> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| BridgeError::InvalidUrl(self.base_url.to_string()))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }
}

fn write_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(5))
        .with_max_times(MAX_WRITE_RETRIES)
        .with_jitter()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::PairingSecret;

    fn request_id() -> RequestId {
        PairingSecret::from_bytes([1; 32]).request_id()
    }

    fn payload() -> EncryptedPayload {
        EncryptedPayload {
            iv: "aXY=".into(),
            payload: "cGF5bG9hZA==".into(),
        }
    }

    fn client(server: &mockito::ServerGuard) -> BridgeClient {
        BridgeClient::new(Url::parse(&server.url()).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn publish_treats_conflict_as_already_published() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/request")
            .match_body(mockito::Matcher::PartialJsonString(
                serde_json::json!({ "request_id": request_id().to_string() }).to_string(),
            ))
            .with_status(409)
            .create_async()
            .await;
        assert_eq!(
            client(&server)
                .publish_request(&request_id(), &payload())
                .await
                .unwrap(),
            PublishOutcome::AlreadyPublished
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn publish_retries_server_errors_a_bounded_number_of_times() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/request")
            .with_status(503)
            .expect(MAX_WRITE_RETRIES + 1)
            .create_async()
            .await;
        let result = client(&server)
            .publish_request(&request_id(), &payload())
            .await;
        assert!(matches!(
            result,
            Err(BridgeError::UnexpectedStatus { status }) if status == StatusCode::SERVICE_UNAVAILABLE
        ));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn single_use_reads_are_not_retried() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/request/{}", request_id());
        let mock = server
            .mock("GET", path.as_str())
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        assert!(client(&server).take_request(&request_id()).await.is_err());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn take_request_maps_missing_to_none() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/request/{}", request_id());
        let _mock = server
            .mock("GET", path.as_str())
            .with_status(404)
            .create_async()
            .await;
        assert_eq!(
            client(&server).take_request(&request_id()).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn fetch_response_maps_bridge_states() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/response/{}", request_id());
        let cases = [
            (
                200,
                r#"{"status":"initialized","response":null}"#,
                ResponseState::Initialized,
            ),
            (
                200,
                r#"{"status":"retrieved","response":null}"#,
                ResponseState::Retrieved,
            ),
            (
                200,
                r#"{"status":"completed","response":{"iv":"aXY=","payload":"cGF5bG9hZA=="}}"#,
                ResponseState::Completed(payload()),
            ),
            (404, "", ResponseState::NotFound),
        ];
        for (status, body, expected) in cases {
            let mock = server
                .mock("GET", path.as_str())
                .with_status(status)
                .with_body(body)
                .create_async()
                .await;
            assert_eq!(
                client(&server).fetch_response(&request_id()).await.unwrap(),
                expected
            );
            mock.remove_async().await;
        }
    }

    #[tokio::test]
    async fn put_response_reports_first_rejection_as_rejected() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/response/{}", request_id());
        let _mock = server
            .mock("PUT", path.as_str())
            .with_status(400)
            .create_async()
            .await;
        assert_eq!(
            client(&server)
                .put_response(&request_id(), &payload())
                .await
                .unwrap(),
            DeliveryOutcome::Rejected
        );
    }

    #[tokio::test]
    async fn put_response_reports_rejection_after_a_failed_attempt_as_possibly_delivered() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/response/{}", request_id());
        let failed = server
            .mock("PUT", path.as_str())
            .with_status(502)
            .expect(1)
            .create_async()
            .await;
        let _rejected = server
            .mock("PUT", path.as_str())
            .with_status(400)
            .create_async()
            .await;
        assert_eq!(
            client(&server)
                .put_response(&request_id(), &payload())
                .await
                .unwrap(),
            DeliveryOutcome::PossiblyDelivered
        );
        failed.assert_async().await;
    }
}
