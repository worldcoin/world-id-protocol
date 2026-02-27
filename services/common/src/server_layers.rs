use std::time::Duration;

use http::{Request, StatusCode};
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

/// Creates a [`tower_http::timeout::TimeoutLayer`] that responds with
/// `504 Gateway Timeout` when a request exceeds the given duration.
pub fn timeout_layer(timeout_secs: u64) -> tower_http::timeout::TimeoutLayer {
    tower_http::timeout::TimeoutLayer::with_status_code(
        http::StatusCode::GATEWAY_TIMEOUT,
        Duration::from_secs(timeout_secs),
    )
}
