use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    extract::MatchedPath,
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::Request as HttpRequest;
use telemetry_batteries::tracing::middleware::TraceLayer;
use tower::Layer;

pub const METRICS_HTTP_LATENCY_MS: &str = "http.latency_ms";

/// Creates a [`TraceLayer`] with method and path on every request span.
pub fn trace_layer() -> TraceLayer {
    TraceLayer::default()
}

/// Records request latency metrics with route, method, and status class tags.
pub async fn request_latency_middleware(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or_else(|| request.uri().path())
        .to_string();
    let started = std::time::Instant::now();

    let response = next.run(request).await;
    let latency_ms = started.elapsed().as_millis() as f64;

    record_http_latency_ms(
        &route,
        method.as_str(),
        response.status().as_u16(),
        latency_ms,
    );

    response
}

fn record_http_latency_ms(route: &str, method: &str, status: u16, latency_ms: f64) {
    let status_class = match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    };

    ::metrics::histogram!(
        METRICS_HTTP_LATENCY_MS,
        "route" => normalize_route(route),
        "method" => method.to_string(),
        "status_class" => status_class
    )
    .record(latency_ms);
}

fn normalize_route(route: &str) -> String {
    route.replace('{', ":").replace('}', "")
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

impl<S, R, B> tower::Service<HttpRequest<B>> for StructuredTimeout<S, R>
where
    S: tower::Service<HttpRequest<B>, Response = axum::response::Response> + Clone + Send + 'static,
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

    fn call(&mut self, req: HttpRequest<B>) -> Self::Future {
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
