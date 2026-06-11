//! Per-endpoint RPC transport metrics.
//!
//! The provider built by [`ProviderArgs`](crate::ProviderArgs) fans every
//! request out to all configured endpoints through alloy's `FallbackLayer`,
//! returning the first successful response. That makes per-endpoint health
//! invisible from the outside: a healthy endpoint masks a failing one. The
//! [`MeteredTransport`] wrapper sits below the fallback layer, around each
//! individual transport, and records which endpoint actually served each
//! request.

use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use alloy::{
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    transports::{TransportError, TransportFut},
};
use tower::Service;
use url::Url;

/// Counter: completed RPC transport calls, labels `endpoint` and `status`
/// (`"success"` / `"error"`).
pub const METRICS_RPC_ENDPOINT_REQUESTS: &str = "rpc.endpoint_requests";
/// Histogram: latency of completed RPC transport calls in milliseconds,
/// label `endpoint`.
pub const METRICS_RPC_ENDPOINT_LATENCY_MS: &str = "rpc.endpoint_latency_ms";

/// Register descriptions for the provider transport metrics.
///
/// Services that build a provider via [`ProviderArgs`](crate::ProviderArgs)
/// should call this from their own `describe_metrics()`.
pub fn describe_provider_metrics() {
    ::metrics::describe_counter!(
        METRICS_RPC_ENDPOINT_REQUESTS,
        ::metrics::Unit::Count,
        "Completed RPC transport calls per endpoint, labelled by endpoint host and outcome."
    );
    ::metrics::describe_histogram!(
        METRICS_RPC_ENDPOINT_LATENCY_MS,
        ::metrics::Unit::Milliseconds,
        "Latency of completed RPC transport calls per endpoint."
    );
}

/// Derive a low-cardinality, secret-free metric label from an RPC URL:
/// the host, plus `:port` when the port is non-default for the scheme.
///
/// Never the full URL — provider URLs (e.g. Alchemy) embed API keys in
/// the path.
fn endpoint_label(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown");
    // `Url::port()` is `None` when the port matches the scheme default.
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// Wraps a single RPC transport and records per-endpoint request metrics.
///
/// # Cancellation semantics
///
/// This service sits *below* alloy's `FallbackLayer`, which fans a request
/// out to several transports in parallel and drops the losing in-flight
/// futures as soon as one succeeds. A dropped future never reaches the
/// recording code, so metrics are only emitted for calls that ran to
/// completion. This is intentional: `rpc.endpoint_requests{status="success"}`
/// answers "which endpoint actually served the request", not "which
/// endpoints were attempted".
///
/// `status="error"` means a transport-level failure (connection error,
/// timeout, non-2xx HTTP). A well-formed JSON-RPC *error response* still
/// counts as `success` here — the endpoint did serve the request.
#[derive(Debug, Clone)]
pub(crate) struct MeteredTransport<S> {
    endpoint: Arc<str>,
    inner: S,
}

impl<S> MeteredTransport<S> {
    /// Wrap `inner`, labelling its metrics with the host of `url`.
    pub(crate) fn new(url: &Url, inner: S) -> Self {
        Self {
            endpoint: endpoint_label(url).into(),
            inner,
        }
    }
}

impl<S> Service<RequestPacket> for MeteredTransport<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    // Must be exactly `TransportFut<'static>`: the `FallbackService` this
    // feeds into requires `S: Service<RequestPacket, Future = TransportFut<'static>, ...>`.
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let endpoint = self.endpoint.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let start = Instant::now();
            let result = inner.call(req).await;

            let status = if result.is_ok() { "success" } else { "error" };
            ::metrics::counter!(
                METRICS_RPC_ENDPOINT_REQUESTS,
                "endpoint" => endpoint.to_string(),
                "status" => status
            )
            .increment(1);
            ::metrics::histogram!(
                METRICS_RPC_ENDPOINT_LATENCY_MS,
                "endpoint" => endpoint.to_string()
            )
            .record(start.elapsed().as_secs_f64() * 1000.0);

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_label_elides_default_port() {
        let url: Url = "https://worldchain-mainnet.g.alchemy.com/v2/secret-api-key"
            .parse()
            .unwrap();
        assert_eq!(endpoint_label(&url), "worldchain-mainnet.g.alchemy.com");
    }

    #[test]
    fn endpoint_label_includes_non_default_port() {
        let url: Url = "http://worldchain-rpc.internal.worldcoin.dev:9545"
            .parse()
            .unwrap();
        assert_eq!(
            endpoint_label(&url),
            "worldchain-rpc.internal.worldcoin.dev:9545"
        );
    }

    #[test]
    fn endpoint_label_never_contains_path() {
        let url: Url = "https://example.com/v2/secret-api-key".parse().unwrap();
        assert!(!endpoint_label(&url).contains("secret-api-key"));
    }
}
