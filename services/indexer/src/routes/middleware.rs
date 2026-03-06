//! HTTP metrics middleware.

use axum::{extract::Request, middleware::Next, response::Response};

/// Records request latency metrics with route and status class tags.
pub async fn request_latency_middleware(request: Request, next: Next) -> Response {
    let route = request.uri().path().to_string();
    let started = std::time::Instant::now();

    let response = next.run(request).await;
    let latency_ms = started.elapsed().as_millis() as f64;

    crate::metrics::record_http_latency_ms(&route, response.status().as_u16(), latency_ms);

    response
}
