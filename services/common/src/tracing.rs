use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// Creates a [`TraceLayer`] configured to emit spans at INFO level.
///
/// By default, `TraceLayer::new_for_http()` emits spans at DEBUG level,
/// which are filtered out by the default `info` log level filter.
/// This function configures all trace components to use INFO level
/// so HTTP traces are visible in Datadog and other collectors.
pub fn trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    DefaultMakeSpan,
    DefaultOnRequest,
    DefaultOnResponse,
> {
    TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
}
