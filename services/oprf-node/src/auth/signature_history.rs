//! Signature History Tracking
//!
//! This module provides [`SignatureHistory`], which tracks nonce signatures
//! to detect replay attacks. It uses a time-based cache that automatically
//! evicts old entries after the configured maximum age.
//!
//! The history is thread-safe and can be cloned to share across tasks.

use std::time::Duration;

use crate::metrics::METRICS_ID_NODE_SIGNATURE_HISTORY_SIZE;
use moka::future::Cache;
use tracing::instrument;

/// Error returned when a duplicate signature is detected.
#[derive(Debug, thiserror::Error)]
#[error("duplicate signature")]
pub(crate) struct DuplicateSignatureError;

/// Tracks nonce signatures to prevent replay attacks.
///
/// Uses a [`moka::future::Cache`] with time-to-live expiration. Signatures
/// are automatically evicted after the configured maximum age.
#[derive(Clone)]
pub(crate) struct SignatureHistory {
    signatures: Cache<Vec<u8>, ()>,
}

impl SignatureHistory {
    /// Initializes a new signature history with automatic expiration.
    ///
    /// Signatures are automatically evicted after `max_signature_age`.
    ///
    /// # Arguments
    /// * `max_signature_age` - Maximum age for signatures before they expire
    /// * `cache_maintenance_interval` - Interval for running cache maintenance tasks
    pub(crate) fn init(max_signature_age: Duration, cache_maintenance_interval: Duration) -> Self {
        ::metrics::gauge!(METRICS_ID_NODE_SIGNATURE_HISTORY_SIZE).set(0.0);
        let signatures = Cache::builder()
            .time_to_live(max_signature_age)
            .eviction_listener(|_key, _value, cause| {
                tracing::debug!("evicting signature from history because of {cause:?}");
                ::metrics::gauge!(METRICS_ID_NODE_SIGNATURE_HISTORY_SIZE).decrement(1);
            })
            .build();

        // periodically run maintenance tasks on the cache
        // this is needed to update metrics in a timely manner, as the eviction listener is only called when an entry is added/removed/accessed
        tokio::spawn({
            let signatures = signatures.clone();
            let mut interval = tokio::time::interval(cache_maintenance_interval);
            async move {
                loop {
                    interval.tick().await;
                    signatures.run_pending_tasks().await;
                }
            }
        });

        SignatureHistory { signatures }
    }

    /// Adds a signature to the history.
    ///
    /// Returns an error if the signature already exists in the history,
    /// indicating a potential replay attack.
    ///
    /// # Arguments
    /// * `signature` - The signature bytes to track
    ///
    /// # Errors
    /// Returns [`DuplicateSignatureError`] if the signature already exists.
    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn add_signature(
        &self,
        signature: Vec<u8>,
    ) -> Result<(), DuplicateSignatureError> {
        tracing::debug!("add signature to history");
        let entry = self.signatures.entry(signature).or_insert(()).await;
        if !entry.is_fresh() {
            tracing::debug!("duplicate signature");
            return Err(DuplicateSignatureError);
        }
        ::metrics::gauge!(METRICS_ID_NODE_SIGNATURE_HISTORY_SIZE).increment(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_signature_history_duplicate_detection() {
        let max_signature_age = Duration::from_secs(60);
        let cache_maintenance_interval = Duration::from_secs(60);
        let signature_history =
            SignatureHistory::init(max_signature_age, cache_maintenance_interval);

        // First insertion should succeed
        signature_history
            .add_signature(b"foo".to_vec())
            .await
            .expect("can add signature");

        // Second insertion of the same signature should fail
        assert!(
            signature_history
                .add_signature(b"foo".to_vec())
                .await
                .is_err(),
            "duplicate signature should be rejected"
        );

        // Different signature should succeed
        signature_history
            .add_signature(b"bar".to_vec())
            .await
            .expect("can add different signature");

        // Multiple different signatures should all succeed
        for i in 0..10 {
            signature_history
                .add_signature(format!("sig_{i}").into_bytes())
                .await
                .expect("can add unique signature");
        }

        // All previously added signatures should still be rejected
        assert!(
            signature_history
                .add_signature(b"foo".to_vec())
                .await
                .is_err()
        );
        assert!(
            signature_history
                .add_signature(b"bar".to_vec())
                .await
                .is_err()
        );
        assert!(
            signature_history
                .add_signature(b"sig_5".to_vec())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_signature_history_is_clone() {
        let max_signature_age = Duration::from_secs(60);
        let cache_maintenance_interval = Duration::from_secs(60);
        let history1 = SignatureHistory::init(max_signature_age, cache_maintenance_interval);
        let history2 = history1.clone();

        // Add signature via first handle
        history1
            .add_signature(b"shared".to_vec())
            .await
            .expect("can add signature");

        // Should be rejected via second handle (shared state)
        assert!(
            history2.add_signature(b"shared".to_vec()).await.is_err(),
            "cloned history should share state"
        );
    }
}
