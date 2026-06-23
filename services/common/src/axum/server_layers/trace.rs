use telemetry_batteries::tracing::middleware::TraceLayer;

/// Creates a [`TraceLayer`] with method and path on every request span.
pub fn trace_layer() -> TraceLayer {
    TraceLayer::default()
}
