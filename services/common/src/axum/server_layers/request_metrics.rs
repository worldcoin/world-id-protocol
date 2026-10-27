use ::axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};

pub const METRICS_HTTP_LATENCY_MS: &str = "http.latency_ms";

pub fn describe_http_request_metrics() {
    ::metrics::describe_histogram!(
        METRICS_HTTP_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "HTTP request latency in milliseconds, labelled by route, method, and status class."
    );
}

/// Records request latency metrics with route, method, and status class tags.
pub async fn request_latency_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("UNKNOWN")
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
        "route" => route.to_string(),
        "method" => method.to_string(),
        "status_class" => status_class
    )
    .record(latency_ms);
}
