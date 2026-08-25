use http::{Method, header::CONTENT_TYPE};
use tower_http::cors::{Any, CorsLayer};

/// Builds the CORS policy shared by the public protocol HTTP services.
///
/// The gateway and indexer are public APIs, so browser requests from every
/// origin are allowed. Credentials remain disabled.
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE])
}

#[cfg(test)]
mod tests {
    use axum::{Router, routing::get};
    use http::{
        Method, Request, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
            ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
        },
    };
    use tower::ServiceExt;

    use super::*;

    fn app() -> Router {
        Router::new()
            .route("/resource", get(|| async { StatusCode::NO_CONTENT }))
            .layer(cors_layer())
    }

    #[tokio::test]
    async fn every_origin_is_allowed_without_credentials() {
        for origin in ["https://app.example.com", "https://unrelated.example"] {
            let response = app()
                .oneshot(
                    Request::get("/resource")
                        .header(ORIGIN, origin)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                response.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN),
                Some(&http::HeaderValue::from_static("*"))
            );
            assert!(
                !response
                    .headers()
                    .contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS)
            );
        }
    }

    #[tokio::test]
    async fn preflight_allows_public_api_methods_and_json_header() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/resource")
                    .header(ORIGIN, "https://app.example.com")
                    .header(ACCESS_CONTROL_REQUEST_METHOD, Method::POST.as_str())
                    .header(ACCESS_CONTROL_REQUEST_HEADERS, CONTENT_TYPE.as_str())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&http::HeaderValue::from_static("*"))
        );
        assert_eq!(
            response.headers().get(ACCESS_CONTROL_ALLOW_METHODS),
            Some(&http::HeaderValue::from_static("GET,POST,OPTIONS"))
        );
        assert_eq!(
            response.headers().get(ACCESS_CONTROL_ALLOW_HEADERS),
            Some(&http::HeaderValue::from_static("content-type"))
        );
        assert!(
            !response
                .headers()
                .contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
    }
}
