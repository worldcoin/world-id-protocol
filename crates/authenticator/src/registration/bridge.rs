//! A client for the message-bridge that carries registration messages (WIP-110).
//!
//! The bridge keys a request and its response by the same [`RequestId`]. Reading either one is
//! single-use: a retry after a lost reply may report that the message expired or was consumed.
//! Transient failures use bounded exponential backoff and jitter.

use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use backon::{ExponentialBuilder, Retryable as _};
use futures_util::StreamExt as _;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use web_time::Instant;

use super::{BridgeDomain, EncryptedPayload, RequestId, deadline::before};
use crate::service_client::http_client_builder;

/// The message-bridge's body limit, which the largest WIP-109 response fits within.
const MAX_BODY_SIZE: usize = 5 * 1024 * 1024;

/// The time budget of one operation, including its retries and reading the response.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum retries after a transient failure.
const MAX_RETRIES: usize = 3;

/// A client for one bridge deployment.
///
/// Each operation, including retries and response decoding, has a 30-second budget on native
/// and browser clients. Callers must also enforce the bridge session expiry.
///
/// The client reaches only its own deployment: a redirect fails the operation. Native clients
/// do not follow it and report [`BridgeError::UnexpectedStatus`]. Browsers follow redirects
/// before the client sees the response, so there the request may reach the redirect target,
/// and the client rejects its response with [`BridgeError::Redirected`].
#[derive(Clone, Debug)]
pub struct BridgeClient {
    http: reqwest::Client,
    domain: BridgeDomain,
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
    ///
    /// The error carries no URL: the bridge routes contain the request id, which is the only key
    /// to the session.
    #[error("bridge request failed: {0}")]
    Transport(#[source] reqwest::Error),
    /// The bridge answered with a status this operation does not expect.
    #[error("bridge returned unexpected status {status}")]
    UnexpectedStatus {
        /// The HTTP status code.
        status: StatusCode,
        /// Minimum retry delay requested by the bridge.
        retry_after: Option<Duration>,
    },
    /// The browser followed a redirect away from the bridge. The response is not used.
    #[error("the bridge redirected the request")]
    Redirected,
    /// The bridge returned malformed JSON, or a body that contradicts its status.
    #[error("invalid bridge JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The bridge response exceeded the transport body limit.
    #[error("bridge response exceeds the 5 MiB body limit")]
    TooLarge,
    /// The operation exhausted its overall time budget.
    #[error("bridge operation timed out")]
    Timeout,
    /// The bridge URL could not be built from the configured base URL.
    #[error("invalid bridge URL: {0}")]
    InvalidUrl(String),
}

impl From<reqwest::Error> for BridgeError {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error.without_url())
    }
}

/// The body of `POST /request`.
#[derive(Serialize)]
struct PublishRequestBody<'a> {
    request_id: String,
    #[serde(flatten)]
    request: &'a EncryptedPayload,
}

/// The body of `GET /response/:id`.
#[derive(Deserialize)]
#[serde(tag = "status", content = "response", rename_all = "snake_case")]
enum ResponseBody {
    Initialized,
    Retrieved,
    Completed(EncryptedPayload),
}

impl From<ResponseBody> for ResponseState {
    fn from(body: ResponseBody) -> Self {
        match body {
            ResponseBody::Initialized => Self::Initialized,
            ResponseBody::Retrieved => Self::Retrieved,
            ResponseBody::Completed(response) => Self::Completed(response),
        }
    }
}

impl BridgeClient {
    /// Creates a client for the bridge at `https://{domain}`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidUrl`] if the domain does not form a valid URL.
    pub fn new(domain: BridgeDomain) -> Result<Self, BridgeError> {
        let url = Url::parse(&format!("https://{domain}"))
            .map_err(|e| BridgeError::InvalidUrl(e.to_string()))?;
        Self::with_base_url(domain, url)
    }

    /// Creates a client that reaches the bridge deployment named `domain` at `base_url` instead
    /// of `https://{domain}`, e.g. a local deployment in tests.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidUrl`] if `base_url` cannot be a base for the bridge routes.
    pub fn with_base_url(domain: BridgeDomain, base_url: Url) -> Result<Self, BridgeError> {
        if base_url.cannot_be_a_base() {
            return Err(BridgeError::InvalidUrl(base_url.to_string()));
        }
        Ok(Self {
            http: http_client(),
            domain,
            base_url,
        })
    }

    /// Returns the domain of the bridge deployment, as written into a Pairing URI.
    #[must_use]
    pub const fn domain(&self) -> &BridgeDomain {
        &self.domain
    }

    /// Stores the encrypted request under `request_id` (`POST /request`).
    ///
    /// The bridge answers `200` when it stored the request and `409` when it already has one.
    /// Retried on server errors, `429` and transport failures. A retry of a request that the bridge
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
        let url = self.url(&["request"]);
        let body = PublishRequestBody {
            request_id: request_id.to_string(),
            request,
        };
        with_retries(|| async {
            let response = self.send(self.http.post(url.clone()).json(&body)).await?;
            match response.status() {
                StatusCode::OK => Ok(PublishOutcome::Published),
                StatusCode::CONFLICT => Ok(PublishOutcome::AlreadyPublished),
                _ => Err(BridgeError::unexpected_status(&response)),
            }
        })
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
        self.read(self.url(&["request", &request_id.to_string()]))
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
            .read(self.url(&["response", &request_id.to_string()]))
            .await?;
        Ok(body.map_or(ResponseState::NotFound, ResponseState::from))
    }

    /// Stores the encrypted response to `request_id` (`PUT /response/:id`).
    ///
    /// The bridge answers `201` when it stored the response, and `400` or `409` when the session
    /// is gone or already has a response. Retried on server errors, `429` and transport failures,
    /// honoring `Retry-After`.
    ///
    /// # Errors
    ///
    /// Returns an error on other unexpected statuses, or once retries are exhausted.
    pub async fn put_response(
        &self,
        request_id: &RequestId,
        response: &EncryptedPayload,
    ) -> Result<DeliveryOutcome, BridgeError> {
        let url = self.url(&["response", &request_id.to_string()]);
        // Set once an attempt failed in a way that may have stored the response anyway.
        let maybe_stored = AtomicBool::new(false);
        with_retries(|| async {
            let attempt = async {
                let reply = self.send(self.http.put(url.clone()).json(response)).await?;
                match reply.status() {
                    StatusCode::CREATED => Ok(DeliveryOutcome::Delivered),
                    StatusCode::BAD_REQUEST | StatusCode::CONFLICT
                        if maybe_stored.load(Ordering::Relaxed) =>
                    {
                        Ok(DeliveryOutcome::PossiblyDelivered)
                    }
                    StatusCode::BAD_REQUEST | StatusCode::CONFLICT => Ok(DeliveryOutcome::Rejected),
                    _ => Err(BridgeError::unexpected_status(&reply)),
                }
            }
            .await;
            if attempt
                .as_ref()
                .is_err_and(BridgeError::may_have_been_stored)
            {
                maybe_stored.store(true, Ordering::Relaxed);
            }
            attempt
        })
        .await
    }

    async fn read<T: DeserializeOwned>(&self, url: Url) -> Result<Option<T>, BridgeError> {
        with_retries(|| async {
            let response = self.send(self.http.get(url.clone())).await?;
            match response.status() {
                StatusCode::OK => read_json(response).await.map(Some),
                StatusCode::NOT_FOUND => Ok(None),
                _ => Err(BridgeError::unexpected_status(&response)),
            }
        })
        .await
    }

    /// Sends `request`, rejecting a response that a browser fetched from a redirect target.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, BridgeError> {
        let request = request.build()?;
        let url = request.url().clone();
        let response = self.http.execute(request).await?;
        if *response.url() != url {
            return Err(BridgeError::Redirected);
        }
        Ok(response)
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .expect("`with_base_url` accepts only URLs that can be a base")
            .pop_if_empty()
            .extend(segments);
        url
    }
}

impl BridgeError {
    fn unexpected_status(response: &reqwest::Response) -> Self {
        Self::UnexpectedStatus {
            status: response.status(),
            retry_after: response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(retry_after),
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(error) => !(error.is_builder() || error.is_decode()),
            Self::UnexpectedStatus { status, .. } => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
            Self::Redirected
            | Self::InvalidUrl(_)
            | Self::Timeout
            | Self::Json(_)
            | Self::TooLarge => false,
        }
    }

    /// Whether the bridge may have stored a write that failed this way: the request reached
    /// it, or the reply was lost. A `429` means it was not processed.
    fn may_have_been_stored(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::UnexpectedStatus { status, .. } => status.is_server_error(),
            _ => false,
        }
    }

    /// The delay before retrying after this error, given the next `backoff` delay.
    ///
    /// A `Retry-After` from the bridge raises the delay to at least the requested one. Returns
    /// `None`, which stops retrying, once the backoff is exhausted or when the bridge asks to wait
    /// longer than the whole operation may take.
    fn retry_delay(&self, backoff: Option<Duration>) -> Option<Duration> {
        let backoff = backoff?;
        match self {
            Self::UnexpectedStatus {
                retry_after: Some(minimum),
                ..
            } => (*minimum < OPERATION_TIMEOUT).then_some(backoff.max(*minimum)),
            _ => Some(backoff),
        }
    }
}

/// Builds the HTTP client for the bridge, which does not follow redirects where the platform
/// lets it decide.
fn http_client() -> reqwest::Client {
    let builder = http_client_builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = builder.redirect(reqwest::redirect::Policy::none());
    builder.build().expect("the TLS backend initializes")
}

/// Runs `attempt`, retrying transient failures with bounded backoff, within
/// [`OPERATION_TIMEOUT`].
async fn with_retries<T, A, F>(attempt: A) -> Result<T, BridgeError>
where
    A: FnMut() -> F,
    F: Future<Output = Result<T, BridgeError>>,
{
    let retried = attempt
        .retry(retry_backoff())
        .when(BridgeError::is_retryable)
        .adjust(BridgeError::retry_delay);
    before(Instant::now() + OPERATION_TIMEOUT, retried)
        .await
        .unwrap_or(Err(BridgeError::Timeout))
}

fn retry_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(5))
        .with_max_times(MAX_RETRIES)
        .with_jitter()
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

/// Parses a `Retry-After` header: delay seconds or an HTTP date.
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

#[cfg(test)]
mod tests {
    use test_case::test_case;

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
        BridgeClient::with_base_url(
            "bridge.example.org".parse().unwrap(),
            Url::parse(&server.url()).unwrap(),
        )
        .unwrap()
    }

    /// The status of an [`BridgeError::UnexpectedStatus`], to compare results in tables.
    fn status_of<T>(result: Result<T, BridgeError>) -> Result<T, StatusCode> {
        result.map_err(|error| match error {
            BridgeError::UnexpectedStatus { status, .. } => status,
            other => panic!("expected an unexpected status, got {other}"),
        })
    }

    #[test_case(200, Ok(PublishOutcome::Published); "stored")]
    #[test_case(201, Err(StatusCode::CREATED); "another success status")]
    #[test_case(409, Ok(PublishOutcome::AlreadyPublished); "stored by an earlier attempt")]
    #[test_case(400, Err(StatusCode::BAD_REQUEST); "rejected")]
    #[tokio::test]
    async fn publish_request_reports_the_bridge_verdict(
        status: usize,
        expected: Result<PublishOutcome, StatusCode>,
    ) {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/request")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "request_id": request_id().to_string(),
                "iv": "aXY=",
                "payload": "cGF5bG9hZA==",
            })))
            .with_status(status)
            .expect(1)
            .create_async()
            .await;
        let result = client(&server)
            .publish_request(&request_id(), &payload())
            .await;
        assert_eq!(status_of(result), expected);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn transport_errors_do_not_reveal_the_request_id() {
        let request_id = request_id().to_string();
        let error = reqwest::get(format!("http://127.0.0.1:1/request/{request_id}"))
            .await
            .unwrap_err();
        assert!(format!("{error:?}").contains(&request_id));

        let error = BridgeError::from(error);
        assert!(!error.to_string().contains(&request_id));
        assert!(!format!("{error:?}").contains(&request_id));
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let mut server = mockito::Server::new_async().await;
        let redirect = server
            .mock("POST", "/request")
            .with_status(307)
            .with_header("location", "/elsewhere")
            .expect(1)
            .create_async()
            .await;
        let target = server
            .mock("POST", "/elsewhere")
            .expect(0)
            .create_async()
            .await;
        let result = client(&server)
            .publish_request(&request_id(), &payload())
            .await;
        assert_eq!(status_of(result), Err(StatusCode::TEMPORARY_REDIRECT));
        redirect.assert_async().await;
        target.assert_async().await;
    }

    #[test_case(200, r#"{"iv":"aXY=","payload":"cGF5bG9hZA=="}"#, Some(payload()); "taken")]
    #[test_case(404, "", None; "expired or taken before")]
    #[tokio::test]
    async fn take_request_returns_the_stored_request_once(
        status: usize,
        body: &str,
        expected: Option<EncryptedPayload>,
    ) {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", format!("/request/{}", request_id()).as_str())
            .with_status(status)
            .with_body(body)
            .create_async()
            .await;
        assert_eq!(
            client(&server).take_request(&request_id()).await.unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn take_request_rejects_an_oversized_chunked_body_without_retry() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", format!("/request/{}", request_id()).as_str())
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

    #[test_case(200, r#"{"status":"initialized","response":null}"#, ResponseState::Initialized; "initialized")]
    #[test_case(200, r#"{"status":"retrieved","response":null}"#, ResponseState::Retrieved; "retrieved")]
    #[test_case(200, r#"{"status":"completed","response":{"iv":"aXY=","payload":"cGF5bG9hZA=="}}"#, ResponseState::Completed(payload()); "completed")]
    #[test_case(404, "", ResponseState::NotFound; "expired or consumed")]
    #[tokio::test]
    async fn fetch_response_reports_the_session_state(
        status: usize,
        body: &str,
        expected: ResponseState,
    ) {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", format!("/response/{}", request_id()).as_str())
            .with_status(status)
            .with_body(body)
            .create_async()
            .await;
        assert_eq!(
            client(&server).fetch_response(&request_id()).await.unwrap(),
            expected
        );
    }

    #[test_case(r#"{"status":"completed","response":null}"#; "completed without a response")]
    #[test_case(r#"{"status":"retrieved","response":{"iv":"aXY=","payload":"cGF5bG9hZA=="}}"#; "a response before completion")]
    #[test_case(r#"{"status":"expired","response":null}"#; "an unknown status")]
    #[test_case("not json"; "not json")]
    #[tokio::test]
    async fn fetch_response_rejects_a_malformed_body_without_retry(body: &str) {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", format!("/response/{}", request_id()).as_str())
            .with_status(200)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        assert!(matches!(
            client(&server).fetch_response(&request_id()).await,
            Err(BridgeError::Json(_))
        ));
        mock.assert_async().await;
    }

    #[test_case(201, Ok(DeliveryOutcome::Delivered); "stored")]
    #[test_case(400, Ok(DeliveryOutcome::Rejected); "session gone")]
    #[test_case(409, Ok(DeliveryOutcome::Rejected); "response already stored")]
    #[test_case(200, Err(StatusCode::OK); "another success status")]
    #[test_case(403, Err(StatusCode::FORBIDDEN); "forbidden")]
    #[tokio::test]
    async fn put_response_reports_the_bridge_verdict(
        status: usize,
        expected: Result<DeliveryOutcome, StatusCode>,
    ) {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", format!("/response/{}", request_id()).as_str())
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "iv": "aXY=",
                "payload": "cGF5bG9hZA==",
            })))
            .with_status(status)
            .expect(1)
            .create_async()
            .await;
        let result = client(&server)
            .put_response(&request_id(), &payload())
            .await;
        assert_eq!(status_of(result), expected);
        mock.assert_async().await;
    }

    #[test_case(502, 400, DeliveryOutcome::PossiblyDelivered; "rejection after a failure in transit")]
    #[test_case(429, 409, DeliveryOutcome::Rejected; "rejection after a rate limit")]
    #[tokio::test]
    async fn put_response_retries_and_reports_whether_the_first_attempt_may_have_landed(
        first: usize,
        retried: usize,
        expected: DeliveryOutcome,
    ) {
        let mut server = mockito::Server::new_async().await;
        let path = format!("/response/{}", request_id());
        let failed = server
            .mock("PUT", path.as_str())
            .with_status(first)
            .with_header("retry-after", "0")
            .expect(1)
            .create_async()
            .await;
        let _retried = server
            .mock("PUT", path.as_str())
            .with_status(retried)
            .create_async()
            .await;
        assert_eq!(
            client(&server)
                .put_response(&request_id(), &payload())
                .await
                .unwrap(),
            expected
        );
        failed.assert_async().await;
    }

    #[tokio::test]
    async fn server_errors_are_retried_a_bounded_number_of_times() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", format!("/request/{}", request_id()).as_str())
            .with_status(503)
            .expect(MAX_RETRIES + 1)
            .create_async()
            .await;
        assert_eq!(
            status_of(client(&server).take_request(&request_id()).await),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn a_rate_limited_read_is_retried() {
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
    async fn a_retry_after_beyond_the_operation_budget_stops_retrying() {
        let mut server = mockito::Server::new_async().await;
        let limited = server
            .mock("GET", format!("/request/{}", request_id()).as_str())
            .with_status(429)
            .with_header("retry-after", "18446744073709551615")
            .expect(1)
            .create_async()
            .await;
        assert_eq!(
            status_of(client(&server).take_request(&request_id()).await),
            Err(StatusCode::TOO_MANY_REQUESTS)
        );
        limited.assert_async().await;
    }

    #[test_case("120", Some(Duration::from_secs(120)); "seconds")]
    #[test_case("Wed, 21 Oct 2015 07:28:00 GMT", Some(Duration::ZERO); "a past date")]
    #[test_case("invalid", None; "garbage")]
    #[test_case("-1", None; "negative seconds")]
    #[test_case("", None; "empty")]
    fn retry_after_parses_seconds_and_http_dates(value: &str, expected: Option<Duration>) {
        assert_eq!(retry_after(value), expected);
    }

    #[test]
    fn retry_after_measures_a_future_date_from_now() {
        let date = std::time::SystemTime::now() + Duration::from_secs(120);
        let delay = retry_after(&httpdate::fmt_http_date(date)).unwrap();
        assert!(delay > Duration::from_secs(118) && delay <= Duration::from_secs(120));
    }
}
