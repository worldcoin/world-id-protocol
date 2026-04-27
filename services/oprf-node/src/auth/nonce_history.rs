//! Nonce History Tracking
//!
//! This module provides [`NonceHistory`], which tracks nonces used for signatures
//! to detect replay attacks. It uses a time-based cache that automatically
//! evicts old entries after the configured maximum age.
//!
//! The history is thread-safe and can be cloned to share across tasks.

use std::time::Duration;

use crate::{auth::BackgroundTask, metrics::METRICS_ID_NODE_NONCE_HISTORY_SIZE};
use moka::future::Cache;
use tokio_util::sync::CancellationToken;
use world_id_primitives::FieldElement;

#[derive(Debug, thiserror::Error)]
#[error("duplicate nonce - already used")]
pub(crate) struct DuplicateNonce;

/// Tracks nonces used for signatures to prevent replay attacks.
///
/// Uses a [`moka::future::Cache`] with time-to-live expiration. Nonces
/// are automatically evicted after the configured maximum age.
#[derive(Clone)]
pub(crate) struct NonceHistory {
    nonces: Cache<FieldElement, ()>,
}

impl NonceHistory {
    /// Initializes a new nonce history with automatic expiration.
    ///
    /// Nonces are automatically evicted after `max_nonce_age`. Spawns a
    /// background cache maintenance task that respects the supplied
    /// cancellation token; the returned [`tokio::task::JoinHandle`] should
    /// be awaited during graceful shutdown.
    ///
    /// # Arguments
    /// * `max_nonce_age` - Maximum age for nonces before they expire
    /// * `cache_maintenance_interval` - Interval for running cache maintenance tasks
    /// * `cancellation_token` - Token used to signal the maintenance task to shut down
    pub(crate) fn init(
        max_nonce_age: Duration,
        cache_maintenance_interval: Duration,
        cancellation_token: CancellationToken,
    ) -> (Self, BackgroundTask) {
        ::metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).set(0.0);

        let nonces = Cache::builder().time_to_live(max_nonce_age).build();

        let maintenance_task = tokio::spawn(maintenance_task(
            nonces.clone(),
            cache_maintenance_interval,
            cancellation_token,
        ));

        (NonceHistory { nonces }, maintenance_task)
    }

    /// Adds a nonce to the history.
    ///
    /// Returns an error if the nonce already exists in the history,
    /// indicating a potential replay attack.
    ///
    /// # Arguments
    /// * `nonce` - The nonce to track
    ///
    /// # Errors
    /// Returns [`DuplicateNonce`] if the nonce already exists.
    pub(crate) async fn add_nonce(&self, nonce: FieldElement) -> Result<(), DuplicateNonce> {
        let entry = self.nonces.entry(nonce).or_insert(()).await;
        if !entry.is_fresh() {
            return Err(DuplicateNonce);
        }
        Ok(())
    }
}

/// Periodically runs cache maintenance tasks and updates the nonce history
/// size metric until cancellation is requested.
async fn maintenance_task(
    nonces: Cache<FieldElement, ()>,
    cache_maintenance_interval: Duration,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    // shutdown service if the maintenance task panics or exits unexpectedly
    let _drop_guard = cancellation_token.clone().drop_guard();
    let mut interval = tokio::time::interval(cache_maintenance_interval);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                nonces.run_pending_tasks().await;
                let size = nonces.entry_count() as f64;
                ::metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).set(size);
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        }
    }
    tracing::info!("Successfully shutdown NonceHistory cache maintenance task");
    eyre::Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nonce_history_duplicate_detection() {
        let mut rng = rand::thread_rng();
        let max_nonce_age = Duration::from_secs(60);
        let cache_maintenance_interval = Duration::from_secs(60);
        let cancellation_token = CancellationToken::new();
        let (nonce_history, _maintenance_task) = NonceHistory::init(
            max_nonce_age,
            cache_maintenance_interval,
            cancellation_token,
        );

        let foo = FieldElement::random(&mut rng);
        let bar = FieldElement::random(&mut rng);

        // First insertion should succeed
        nonce_history.add_nonce(foo).await.expect("can add nonce");

        // Second insertion of the same nonce should fail
        assert!(
            nonce_history.add_nonce(foo).await.is_err(),
            "duplicate nonce should be rejected"
        );

        // Different nonce should succeed
        nonce_history
            .add_nonce(bar)
            .await
            .expect("can add different nonce");

        // Multiple different nonces should all succeed
        for _ in 0..10 {
            nonce_history
                .add_nonce(FieldElement::random(&mut rng))
                .await
                .expect("can add unique nonce");
        }

        // All previously added nonces should still be rejected
        nonce_history.add_nonce(foo).await.expect_err("Should fail");
        nonce_history.add_nonce(bar).await.expect_err("Should fail");
    }

    #[tokio::test]
    async fn test_nonce_history_is_clone() {
        let max_nonce_age = Duration::from_secs(60);
        let cache_maintenance_interval = Duration::from_secs(60);
        let cancellation_token = CancellationToken::new();
        let (history1, _maintenance_task) = NonceHistory::init(
            max_nonce_age,
            cache_maintenance_interval,
            cancellation_token,
        );
        let history2 = history1.clone();

        let shared = FieldElement::random(&mut rand::thread_rng());

        // Add nonce via first handle
        history1.add_nonce(shared).await.expect("can add nonce");

        // Should be rejected via second handle (shared state)
        assert!(
            history2.add_nonce(shared).await.is_err(),
            "cloned history should share state"
        );
    }

    #[tokio::test]
    async fn test_nonce_history_ttl_expiration() {
        let nonce = FieldElement::random(&mut rand::thread_rng());
        let max_nonce_age = Duration::from_secs(1);
        let cache_maintenance_interval = Duration::from_millis(100);
        let cancellation_token = CancellationToken::new();
        let (nonce_history, _maintenance_task) = NonceHistory::init(
            max_nonce_age,
            cache_maintenance_interval,
            cancellation_token,
        );

        // Add nonce — should succeed
        nonce_history.add_nonce(nonce).await.expect("can add nonce");

        // Immediately - should be rejected
        nonce_history
            .add_nonce(nonce)
            .await
            .expect_err("duplicate should fail");

        // Wait for TTL + maintenance to expire it
        tokio::time::sleep(Duration::from_secs(2)).await;

        // After TTL expiration - should succeed again
        nonce_history
            .add_nonce(nonce)
            .await
            .expect("nonce should be accepted after TTL expiration");
    }
}
