//! A client for the message-bridge that carries registration messages (WIP-110).
//!
//! The bridge keys a request and its response by the same [`RequestId`]. Reading either one is
//! single-use: a retry after a lost reply may report that the message expired or was consumed.
//! Transient failures use bounded exponential backoff and jitter.

use std::{future::Future, time::Duration};

use backon::{ExponentialBuilder, Retryable as _, Sleeper as _};
use futures_util::{
    StreamExt as _,
    future::{Either, select},
};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{BridgeDomain, EncryptedPayload, RequestId};
use crate::service_client::default_http_client;

/// Maximum retries after a transient failure.
const MAX_RETRIES: usize = 3;
const MAX_BODY_SIZE: usize = 24 * 1024 * 1024;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// A client for one bridge deployment.
///
/// Each operation, including retries and response decoding, has a 30-second budget on native
/// and browser clients. Callers must also enforce the bridge session expiry.
#[derive(Clone, Debug)]
pub struct BridgeClient {
    http: reqwest::Client,
    base_url: Url,
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
    /// stored before the reply was lost yields [`PublishOutcome::AlreadyPublished`]. In the rare
    /// case that the Approving Authenticator took the request in between, the retry stores it
    /// again and resets the session status to `initialized`, as WIP-109 accepts.
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
                _ => Err(BridgeError::from_response(&response)),
            }
        };
        bounded(
            send.retry(backoff())
                .when(BridgeError::is_retryable)
                .adjust(BridgeError::retry_delay),
        )
        .await
    }

    /// Takes the encrypted request stored under `request_id` (`GET /request/:id`).
    ///
    /// Returns `None` if the request expired or was already taken, including when an earlier
    /// attempt consumed it but its reply was lost. Retries transient failures with bounded backoff.
    ///
    /// # Errors
    ///
    /// Returns an error on malformed data, unexpected statuses, or exhausted retries/deadline.
    pub async fn take_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<EncryptedPayload>, BridgeError> {
        self.read(self.url(&["request", &request_id.to_string()])?)
            .await
    }

    /// Reads the response state, consuming the response if it has arrived.
    ///
    /// Retries transient failures, honoring `Retry-After`. A retry after a consumed response was
    /// lost can return [`ResponseState::NotFound`]; the caller must start a new pairing.
    ///
    /// # Errors
    ///
    /// Returns an error on malformed data, unexpected statuses, or exhausted retries/deadline.
    pub async fn fetch_response(
        &self,
        request_id: &RequestId,
    ) -> Result<ResponseState, BridgeError> {
        let body: Option<ResponseBody> = self
            .read(self.url(&["response", &request_id.to_string()])?)
            .await?;
        match body {
            None => Ok(ResponseState::NotFound),
            Some(ResponseBody {
                status: WireStatus::Completed,
                response: Some(payload),
            }) => Ok(ResponseState::Completed(payload)),
            Some(ResponseBody {
                status: WireStatus::Initialized,
                response: None,
            }) => Ok(ResponseState::Initialized),
            Some(ResponseBody {
                status: WireStatus::Retrieved,
                response: None,
            }) => Ok(ResponseState::Retrieved),
            Some(_) => Err(BridgeError::InvalidResponse(
                "payload does not match response status",
            )),
        }
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
                _ => Err(BridgeError::from_response(&reply)),
            }
        };
        bounded(
            send.retry(backoff())
                .when(BridgeError::is_retryable)
                .adjust(BridgeError::retry_delay),
        )
        .await
    }

    async fn read<T: DeserializeOwned>(&self, url: Url) -> Result<Option<T>, BridgeError> {
        let send = || async {
            let response = self.http.get(url.clone()).send().await?;
            match response.status() {
                StatusCode::OK => Ok(Some(read_json(response).await?)),
                StatusCode::NOT_FOUND => Ok(None),
                _ => Err(BridgeError::from_response(&response)),
            }
        };
        bounded(
            send.retry(backoff())
                .when(BridgeError::read_is_retryable)
                .adjust(BridgeError::retry_delay),
        )
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
        /// Minimum retry delay requested by the bridge.
        retry_after: Option<Duration>,
    },
    /// The bridge returned a response that contradicts its status.
    #[error("invalid bridge response: {0}")]
    InvalidResponse(&'static str),
    /// The bridge returned malformed JSON.
    #[error("invalid bridge JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The bridge response exceeded the transport body limit.
    #[error("bridge response exceeds the 24 MiB body limit")]
    TooLarge,
    /// The operation exhausted its overall time budget.
    #[error("bridge operation timed out")]
    Timeout,
    /// The bridge URL could not be built from the configured base URL.
    #[error("invalid bridge URL: {0}")]
    InvalidUrl(String),
}

impl BridgeError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(error) => !error.is_decode(),
            Self::UnexpectedStatus { status, .. } => status.is_server_error(),
            Self::InvalidUrl(_)
            | Self::InvalidResponse(_)
            | Self::Timeout
            | Self::Json(_)
            | Self::TooLarge => false,
        }
    }

    fn from_response(response: &reqwest::Response) -> Self {
        Self::UnexpectedStatus {
            status: response.status(),
            retry_after: response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(retry_after),
        }
    }

    fn read_is_retryable(&self) -> bool {
        self.is_retryable()
            || matches!(
                self,
                Self::UnexpectedStatus {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    ..
                }
            )
    }

    fn retry_delay(&self, delay: Option<Duration>) -> Option<Duration> {
        let delay = delay?;
        match self {
            Self::UnexpectedStatus {
                retry_after: Some(minimum),
                ..
            } => (*minimum < OPERATION_TIMEOUT).then_some(delay.max(*minimum)),
            _ => Some(delay),
        }
    }
}

fn retry_after(value: &str) -> Option<Duration> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse().ok().map(Duration::from_secs);
    }
    let date = httpdate::parse_http_date(value).ok()?;
    let now = std::time::UNIX_EPOCH
        + web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .ok()?;
    Some(date.duration_since(now).unwrap_or_default())
}

async fn bounded<T>(
    future: impl Future<Output = Result<T, BridgeError>>,
) -> Result<T, BridgeError> {
    let timeout = backon::DefaultSleeper::default().sleep(OPERATION_TIMEOUT);
    match select(std::pin::pin!(future), std::pin::pin!(timeout)).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => Err(BridgeError::Timeout),
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

async fn read_json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, BridgeError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_SIZE as u64)
    {
        return Err(BridgeError::TooLarge);
    }
    let stream = response.bytes_stream();
    let mut stream = std::pin::pin!(stream);
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > MAX_BODY_SIZE - bytes.len() {
            return Err(BridgeError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(5))
        .with_max_times(MAX_RETRIES)
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
    async fn rejects_oversized_chunked_bodies_without_retry() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/request/{}", request_id());
        let mock = server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_chunked_body(|writer| {
                let chunk = [b' '; 64 * 1024];
                for _ in 0..=MAX_BODY_SIZE / chunk.len() {
                    writer.write_all(&chunk)?;
                }
                Ok(())
            })
            .expect(1)
            .create_async()
            .await;
        assert!(matches!(
            client(&server).take_request(&request_id()).await,
            Err(BridgeError::TooLarge)
        ));
        mock.assert_async().await;
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
            .expect(MAX_RETRIES + 1)
            .create_async()
            .await;
        let result = client(&server)
            .publish_request(&request_id(), &payload())
            .await;
        assert!(matches!(
            result,
            Err(BridgeError::UnexpectedStatus { status, .. }) if status == StatusCode::SERVICE_UNAVAILABLE
        ));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn single_use_reads_retry_transient_failures_with_a_bound() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/request/{}", request_id());
        let mock = server
            .mock("GET", path.as_str())
            .with_status(500)
            .expect(MAX_RETRIES + 1)
            .create_async()
            .await;
        assert!(client(&server).take_request(&request_id()).await.is_err());
        mock.assert_async().await;
    }

    #[test]
    fn retry_after_supports_seconds_and_http_dates() {
        assert_eq!(retry_after("120"), Some(Duration::from_secs(120)));
        assert_eq!(
            retry_after("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(Duration::ZERO)
        );
        let future = std::time::SystemTime::now() + Duration::from_secs(120);
        let delay = retry_after(&httpdate::fmt_http_date(future)).unwrap();
        assert!(delay > Duration::from_secs(118) && delay <= Duration::from_secs(120));
        assert_eq!(retry_after("invalid"), None);
        assert_eq!(retry_after("-1"), None);
    }

    #[tokio::test]
    async fn read_retries_rate_limit_then_reports_consumed_request() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/request/{}", request_id());
        let limited = server
            .mock("GET", path.as_str())
            .with_status(429)
            .with_header("retry-after", "0")
            .expect(1)
            .create_async()
            .await;
        let consumed = server
            .mock("GET", path.as_str())
            .with_status(404)
            .expect(1)
            .create_async()
            .await;
        assert_eq!(
            client(&server).take_request(&request_id()).await.unwrap(),
            None
        );
        limited.assert_async().await;
        consumed.assert_async().await;
    }

    #[tokio::test]
    async fn retry_after_beyond_operation_budget_does_not_retry_early() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/request/{}", request_id());
        let limited = server
            .mock("GET", path.as_str())
            .with_status(429)
            .with_header("retry-after", "18446744073709551615")
            .expect(1)
            .create_async()
            .await;
        assert!(matches!(
            client(&server).take_request(&request_id()).await,
            Err(BridgeError::UnexpectedStatus {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            })
        ));
        limited.assert_async().await;
    }

    #[tokio::test]
    async fn malformed_completed_response_is_an_error_without_retry() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/response/{}", request_id());
        let malformed = server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_body(r#"{"status":"completed","response":null}"#)
            .expect(1)
            .create_async()
            .await;
        assert!(matches!(
            client(&server).fetch_response(&request_id()).await,
            Err(BridgeError::InvalidResponse(_))
        ));
        malformed.assert_async().await;
    }

    #[tokio::test]
    async fn malformed_json_is_not_retried_after_consuming_request() {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/request/{}", request_id());
        let malformed = server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_body("not json")
            .expect(1)
            .create_async()
            .await;
        assert!(matches!(
            client(&server).take_request(&request_id()).await,
            Err(BridgeError::Json(_))
        ));
        malformed.assert_async().await;
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
