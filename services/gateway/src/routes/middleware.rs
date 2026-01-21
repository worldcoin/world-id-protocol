//! Request ID middleware.

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use uuid::Uuid;

/// Canonical request ID attached to every request.
#[derive(Clone, Copy, Debug)]
pub struct RequestId(pub Uuid);

/// Middleware that generates and attaches a canonical request ID.
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4();
    request.extensions_mut().insert(RequestId(request_id));

    let mut response = next.run(request).await;

    // Add to response headers for client correlation
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert("X-Request-Id", value);
    }

    response
}
