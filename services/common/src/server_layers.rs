use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::response::IntoResponse;
use http::{Request, StatusCode};
use tower::Layer;
use tower_http::trace::{DefaultOnRequest, MakeSpan, OnResponse, TraceLayer};
use tracing::Span;

/// Custom span maker that includes HTTP method and path in every request
/// span.
#[derive(Clone, Debug)]
pub struct MakeRequestSpan;

impl<B> MakeSpan<B> for MakeRequestSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        // don't create a span for /health endpoint
        if request.uri().path() == "/health" {
            return Span::none();
        }

        tracing::debug_span!(
            "request",
            method = %request.method(),
            path = %request.uri(),
        )
    }
}

/// Custom response handler that only logs when there's an active span
#[derive(Clone)]
pub struct ConditionalOnResponse;

impl<B> OnResponse<B> for ConditionalOnResponse {
    fn on_response(
        self,
        response: &axum::http::Response<B>,
        latency: std::time::Duration,
        span: &Span,
    ) {
        let message = format!(
            "{}Request completed with status {} in {}ms",
            if response.status() == StatusCode::BAD_REQUEST {
                "🟡 Bad "
            } else {
                ""
            },
            response.status(),
            latency.as_millis()
        );

        let error_status = [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ];

        if error_status.contains(&response.status()) {
            tracing::error!(
                message,
                status = %response.status(),
                latency = ?latency,
            );
        } else if !span.is_disabled() && response.status() != StatusCode::NOT_FOUND {
            tracing::debug!(
                message,
                status = %response.status(),
                latency = ?latency,
            );
        }
    }
}

/// Creates a [`TraceLayer`] with method and path on every request span.
pub fn trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    MakeRequestSpan,
    DefaultOnRequest,
    ConditionalOnResponse,
> {
    TraceLayer::new_for_http()
        .make_span_with(MakeRequestSpan)
        .on_response(ConditionalOnResponse)
}

/// Tower layer that responds with a caller-supplied structured error when a
/// request exceeds the configured timeout.
///
/// `R` is a clonable response value (e.g. `GatewayErrorResponse` or
/// `IndexerErrorResponse`). On each timeout the layer clones `R` and converts
/// it into an HTTP response via [`IntoResponse`].
#[derive(Clone)]
pub struct StructuredTimeoutLayer<R> {
    timeout: Duration,
    timeout_response: R,
}

impl<S, R> Layer<S> for StructuredTimeoutLayer<R>
where
    R: Clone,
{
    type Service = StructuredTimeout<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        StructuredTimeout {
            inner,
            timeout: self.timeout,
            timeout_response: self.timeout_response.clone(),
        }
    }
}

#[derive(Clone)]
pub struct StructuredTimeout<S, R> {
    inner: S,
    timeout: Duration,
    timeout_response: R,
}

impl<S, R, B> tower::Service<Request<B>> for StructuredTimeout<S, R>
where
    S: tower::Service<Request<B>, Response = axum::response::Response> + Clone + Send + 'static,
    S::Future: Send,
    R: Clone + IntoResponse + Send + 'static,
    B: Send + 'static,
{
    type Response = axum::response::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let timeout = self.timeout;
        let timeout_response = self.timeout_response.clone();
        let mut inner = self.inner.clone();
        std::mem::swap(&mut self.inner, &mut inner);
        Box::pin(async move {
            match tokio::time::timeout(timeout, inner.call(req)).await {
                Ok(result) => result,
                Err(_) => Ok(timeout_response.into_response()),
            }
        })
    }
}

/// Creates a layer that responds with the given structured error when a
/// request exceeds `timeout_secs`.
///
/// `timeout_response` must be [`Clone`] + [`IntoResponse`]; each service
/// passes its own typed error (e.g. `GatewayErrorResponse::request_timeout`).
pub fn timeout_layer<R>(timeout_secs: u64, timeout_response: R) -> StructuredTimeoutLayer<R>
where
    R: Clone + IntoResponse + Send + 'static,
{
    StructuredTimeoutLayer {
        timeout: Duration::from_secs(timeout_secs),
        timeout_response,
    }
}
