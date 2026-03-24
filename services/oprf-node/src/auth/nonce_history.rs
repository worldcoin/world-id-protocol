//! Nonce History Tracking
//!
//! This module provides [`NonceHistory`], which tracks nonces used for signatures
//! to detect replay attacks. It uses a time-based cache that automatically
//! evicts old entries after the configured maximum age.
//!
//! The history is thread-safe and can be cloned to share across tasks.

use std::time::Duration;

use crate::metrics::METRICS_ID_NODE_NONCE_HISTORY_SIZE;
use moka::future::Cache;
use tracing::instrument;
use world_id_core::FieldElement;
use world_id_primitives::oprf::WorldIdRequestAuthError;

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
    /// Nonces are automatically evicted after `max_nonce_age`.
    ///
    /// # Arguments
    /// * `max_nonce_age` - Maximum age for nonces before they expire
    /// * `cache_maintenance_interval` - Interval for running cache maintenance tasks
    pub(crate) fn init(max_nonce_age: Duration, cache_maintenance_interval: Duration) -> Self {
        ::metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).set(0.0);

        let nonces = Cache::builder().time_to_live(max_nonce_age).build();

        // periodically run maintenance tasks on the cache and update metrics
        tokio::spawn({
            let nonces = nonces.clone();
            let mut interval = tokio::time::interval(cache_maintenance_interval);
            async move {
                loop {
                    interval.tick().await;
                    nonces.run_pending_tasks().await;
                    let size = nonces.entry_count() as f64;
                    ::metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).set(size);
                }
            }
        });

        NonceHistory { nonces }
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
    /// Returns [`WorldIdRequestAuthError::DuplicateNonce`] if the nonce already exists.
    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn add_nonce(
        &self,
        nonce: FieldElement,
    ) -> Result<(), WorldIdRequestAuthError> {
        tracing::debug!("add nonce to history");
        let entry = self.nonces.entry(nonce).or_insert(()).await;
        if !entry.is_fresh() {
            tracing::debug!("duplicate nonce");
            return Err(WorldIdRequestAuthError::DuplicateNonce);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nonce_history_duplicate_detection() {
        let mut rng = rand::thread_rng();
        let max_nonce_age = Duration::from_secs(60);
        let cache_maintenance_interval = Duration::from_secs(60);
        let nonce_history = NonceHistory::init(max_nonce_age, cache_maintenance_interval);

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
        let history1 = NonceHistory::init(max_nonce_age, cache_maintenance_interval);
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
}
