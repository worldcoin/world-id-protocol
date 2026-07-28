use ::axum::{
    extract::{MatchedPath, Request},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};

/// Counter for requests to HTTP endpoints scheduled for removal.
pub const METRICS_DEPRECATED_ENDPOINT_REQUESTS: &str = "http.deprecated_endpoint_requests";

/// The date these endpoints were formally marked as deprecated, encoded as an
/// RFC 9651 date per RFC 9745.
const DEPRECATION: HeaderValue = HeaderValue::from_static("@1785110400");
/// One year after formal deprecation, encoded as an HTTP-date per RFC 8594.
const SUNSET: HeaderValue = HeaderValue::from_static("Tue, 27 Jul 2027 00:00:00 GMT");

pub fn describe_deprecated_endpoint_metrics() {
    ::metrics::describe_counter!(
        METRICS_DEPRECATED_ENDPOINT_REQUESTS,
        ::metrics::Unit::Count,
        "Number of requests to deprecated HTTP endpoints, labelled by route and method."
    );
}

/// Adds deprecation metadata and records use of an endpoint scheduled for removal.
pub async fn deprecated_endpoint_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("UNKNOWN")
        .to_string();

    tracing::warn!(
        route,
        method = method.as_str(),
        sunset = "2027-07-27T00:00:00Z",
        "deprecated endpoint used"
    );
    ::metrics::counter!(
        METRICS_DEPRECATED_ENDPOINT_REQUESTS,
        "route" => route,
        "method" => method.to_string()
    )
    .increment(1);

    let mut response = next.run(request).await;
    response.headers_mut().insert("deprecation", DEPRECATION);
    response.headers_mut().insert("sunset", SUNSET);
    response
}
