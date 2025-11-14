use std::time::Duration;

/// Async sleep helper that abstracts over the underlying runtime.
pub async fn sleep(duration: Duration) {
    platform_sleep(duration).await;
}

#[cfg(not(target_arch = "wasm32"))]
async fn platform_sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
async fn platform_sleep(duration: Duration) {
    gloo_timers::future::sleep(duration).await;
}
