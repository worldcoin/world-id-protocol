//! Request ID and metrics middleware.

use crate::metrics::METRICS_REQUESTS_LATENCY_MS;
use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use uuid::Uuid;

/// Canonical request ID attached to every request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RequestId(pub Uuid);

/// Middleware that generates and attaches a canonical request ID,
/// and records request latency metrics.
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4();
    let path = request.uri().path().to_string();
    let method = request.method().to_string();

    request.extensions_mut().insert(RequestId(request_id));

    let start = std::time::Instant::now();
    let mut response = next.run(request).await;
    let latency_ms = start.elapsed().as_millis() as f64;

    // Record latency metric
    ::metrics::histogram!(
        METRICS_REQUESTS_LATENCY_MS,
        "method" => method,
        "path" => normalize_path(&path),
        "status" => response.status().as_u16().to_string()
    )
    .record(latency_ms);

    // Add to response headers for client correlation
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert("X-Request-Id", value);
    }

    response
}

/// Normalize path to avoid high cardinality from dynamic segments.
fn normalize_path(path: &str) -> String {
    // Replace dynamic segments like /status/{id} with /status/:id
    if path.starts_with("/status/") {
        return "/status/:id".to_string();
    }
    path.to_string()
}
