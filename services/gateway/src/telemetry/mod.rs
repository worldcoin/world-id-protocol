//! Telemetry infrastructure for the World ID Gateway.
//!
//! This module provides:
//! - OpenTelemetry integration for distributed tracing
//! - Custom `MetricsSpanProcessor` that records metrics on span start/end
//! - Helpers for initializing the telemetry pipeline

mod processor;

pub use processor::{BatcherMetrics, MetricsSpanProcessor, SpanMetrics};

use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{Config, Sampler, TracerProvider as SdkTracerProvider},
    Resource,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Configuration for the telemetry system.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// OTLP endpoint for trace export (e.g., "http://localhost:4317").
    /// If None, tracing export is disabled.
    pub otlp_endpoint: Option<String>,
    /// Service name for resource identification.
    pub service_name: String,
    /// Service version.
    pub service_version: String,
    /// Sampling ratio (0.0 to 1.0).
    pub sampling_ratio: f64,
    /// Whether to enable JSON logging.
    pub json_logging: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            service_name: "world-id-gateway".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            sampling_ratio: 1.0,
            json_logging: true,
        }
    }
}

/// Initialize the telemetry pipeline.
///
/// Returns:
/// - `SpanMetrics` for accessing span-derived metrics
/// - `Option<SdkTracerProvider>` if OTLP export is enabled (for graceful shutdown)
pub fn init(config: TelemetryConfig) -> anyhow::Result<(SpanMetrics, Option<SdkTracerProvider>)> {
    let span_metrics = SpanMetrics::new();
    let metrics_processor = MetricsSpanProcessor::new(span_metrics.clone());

    // Build resource for trace identification
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", config.service_version.clone()),
    ]);

    // Build the tracer provider with our custom metrics processor
    let mut provider_builder = SdkTracerProvider::builder()
        .with_config(
            Config::default()
                .with_sampler(Sampler::TraceIdRatioBased(config.sampling_ratio))
                .with_resource(resource),
        )
        .with_span_processor(metrics_processor);

    // Add OTLP exporter if endpoint is configured
    if let Some(endpoint) = &config.otlp_endpoint {
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint)
            .build_span_exporter()?;

        provider_builder = provider_builder.with_batch_exporter(exporter, runtime::Tokio);
    }

    let tracer_provider = provider_builder.build();

    // Set up the tracing subscriber layers
    let env_filter = EnvFilter::new(
        std::env::var("RUST_LOG")
            .unwrap_or_else(|_| "world_id_gateway=info,axum=info,tower_http=info".into()),
    );

    // Create OpenTelemetry layer
    let tracer = tracer_provider.tracer(config.service_name.clone());
    let otel_layer = OpenTelemetryLayer::new(tracer);

    // Create fmt layer
    let fmt_layer = if config.json_logging {
        tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer)
        .with(fmt_layer)
        .init();

    Ok((span_metrics, Some(tracer_provider)))
}

/// Shutdown the telemetry pipeline gracefully.
pub fn shutdown(provider: Option<SdkTracerProvider>) {
    if let Some(provider) = provider {
        if let Err(e) = provider.shutdown() {
            tracing::error!(error = ?e, "telemetry.shutdown_failed");
        }
    }
}
