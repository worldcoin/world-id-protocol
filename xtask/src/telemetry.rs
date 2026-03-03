//! Declarative telemetry initialization for xtask.

/// Initialize structured tracing for xtask.
///
/// Respects `RUST_LOG` when set, otherwise falls back to the provided filter.
/// ANSI colors are disabled for clean, parseable output.
///
/// # Examples
///
/// ```ignore
/// telemetry!();                           // default: "info"
/// telemetry!("debug");                    // custom level
/// telemetry!("xtask=debug,relay=trace");  // per-target
/// ```
macro_rules! telemetry {
    () => {
        telemetry!("info")
    };
    ($filter:expr) => {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new($filter)),
            )
            .with_target(true)
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .init();
    };
}

// Re-exported via `#[macro_use]` on the module declaration in main.rs.
