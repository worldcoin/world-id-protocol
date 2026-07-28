use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use ::axum::{extract::MatchedPath, http::HeaderValue};
use tower::{Layer, Service};

/// Counter for requests to HTTP endpoints scheduled for removal.
pub const METRICS_DEPRECATED_ENDPOINT_REQUESTS: &str = "http.deprecated_endpoint_requests";

/// Static metadata describing one API deprecation.
pub trait Deprecation {
    /// Stable identifier used to distinguish deprecations in telemetry.
    const ID: &'static str;
    /// Date the endpoint was deprecated, encoded as an RFC 9651 date per RFC 9745.
    const DEPRECATED_AT: &'static str;
    /// Date the endpoint is scheduled for removal, encoded as an HTTP-date per RFC 8594.
    const SUNSET: &'static str;
}

/// Generic Tower layer that adds deprecation headers and usage telemetry.
pub struct DeprecationLayer<D>(PhantomData<fn() -> D>);

impl<D> DeprecationLayer<D> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<D> Clone for DeprecationLayer<D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<D> Copy for DeprecationLayer<D> {}

impl<D> Default for DeprecationLayer<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, D> Layer<S> for DeprecationLayer<D> {
    type Service = DeprecationService<S, D>;

    fn layer(&self, inner: S) -> Self::Service {
        DeprecationService {
            inner,
            deprecation: PhantomData,
        }
    }
}

/// Service produced by [`DeprecationLayer`].
pub struct DeprecationService<S, D> {
    inner: S,
    deprecation: PhantomData<fn() -> D>,
}

impl<S: Clone, D> Clone for DeprecationService<S, D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            deprecation: PhantomData,
        }
    }
}

impl<S, D, RequestBody, ResponseBody> Service<http::Request<RequestBody>>
    for DeprecationService<S, D>
where
    S: Service<http::Request<RequestBody>, Response = http::Response<ResponseBody>>,
    S::Future: Send + 'static,
    D: Deprecation,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<RequestBody>) -> Self::Future {
        let method = request.method().clone();
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str)
            .unwrap_or("UNKNOWN")
            .to_string();

        tracing::warn!(
            deprecation = D::ID,
            route,
            method = method.as_str(),
            sunset = D::SUNSET,
            "deprecated endpoint used"
        );
        ::metrics::counter!(
            METRICS_DEPRECATED_ENDPOINT_REQUESTS,
            "deprecation" => D::ID,
            "route" => route,
            "method" => method.to_string()
        )
        .increment(1);

        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response = future.await?;
            response
                .headers_mut()
                .insert("deprecation", HeaderValue::from_static(D::DEPRECATED_AT));
            response
                .headers_mut()
                .insert("sunset", HeaderValue::from_static(D::SUNSET));
            Ok(response)
        })
    }
}

/// Deprecation of the V1 recovery-agent management API after the V2 upgrade.
pub enum V2RecoveryAgentDeprecation {}

impl Deprecation for V2RecoveryAgentDeprecation {
    const ID: &'static str = "v2_recovery_agent";
    // Mon, 27 Jul 2026 00:00:00 GMT, encoded as an RFC 9651 date.
    const DEPRECATED_AT: &'static str = "@1785110400";
    const SUNSET: &'static str = "Tue, 27 Jul 2027 00:00:00 GMT";
}

pub type V2RecoveryAgentDeprecationLayer = DeprecationLayer<V2RecoveryAgentDeprecation>;

pub fn describe_deprecated_endpoint_metrics() {
    ::metrics::describe_counter!(
        METRICS_DEPRECATED_ENDPOINT_REQUESTS,
        ::metrics::Unit::Count,
        "Number of requests to deprecated HTTP endpoints, labelled by deprecation, route, and method."
    );
}
