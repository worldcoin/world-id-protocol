use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use tower::ServiceExt;
use world_id_services_common::{
    Deprecation, DeprecationLayer, METRICS_DEPRECATED_ENDPOINT_REQUESTS,
};

struct TestDeprecation;

impl Deprecation for TestDeprecation {
    const ID: &'static str = "test_deprecation";
    const DEPRECATED_AT: &'static str = "@1785110400";
    const SUNSET: &'static str = "Tue, 27 Jul 2027 00:00:00 GMT";
}

#[tokio::test]
async fn deprecation_layer_adds_headers_and_records_usage() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("install debugging recorder");

    let app = Router::new().route(
        "/deprecated",
        get(|| async { StatusCode::NO_CONTENT })
            .route_layer(DeprecationLayer::<TestDeprecation>::new()),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/deprecated")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["deprecation"], "@1785110400");
    assert_eq!(
        response.headers()["sunset"],
        "Tue, 27 Jul 2027 00:00:00 GMT"
    );

    let count = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _unit, _description, value)| {
            let key = key.key();
            let has_label = |name: &str, expected: &str| {
                key.labels()
                    .any(|label| label.key() == name && label.value() == expected)
            };

            match value {
                DebugValue::Counter(value)
                    if key.name() == METRICS_DEPRECATED_ENDPOINT_REQUESTS
                        && has_label("deprecation", "test_deprecation")
                        && has_label("route", "/deprecated")
                        && has_label("method", "GET") =>
                {
                    Some(value)
                }
                _ => None,
            }
        })
        .sum::<u64>();

    assert_eq!(count, 1);
}
