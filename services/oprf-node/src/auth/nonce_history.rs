//! Nonce History Tracking
//!
//! This module provides [`NonceHistory`], an in-memory replay filter for
//! RP-signed request nonces. It uses a time-based cache that automatically
//! evicts old entries after the configured maximum age.
//!
//! The history is thread-safe and can be cloned to share across tasks, but only
//! within the same process and module instance. It does not coordinate with
//! other OPRF nodes or with other replicas that keep their own in-memory state.
//! In a 2-of-4 deployment, for example, a client can query nodes A/B and then
//! C/D with the same RP-signed nonce, and both subsets can accept it because
//! each subset sees a fresh local history. The same caveat applies to separate
//! EU/US/SEA replicas, or any other horizontally scaled deployment.
//!
//! This is acceptable at the protocol level: any additional nullifier produced
//! by a replayed nonce cannot be redeemed, and the extra computation on the
//! OPRF node is negligible. In practice, the deployed system is expected to use
//! a threshold greater than half of the total nodes, making this scenario
//! impossible in the first place — though it may still arise within a single
//! provider's replica set in a multi-provider deployment.

use std::time::Duration;

use crate::metrics::METRICS_ID_NODE_NONCE_HISTORY_SIZE;
use moka::future::Cache;
use world_id_primitives::FieldElement;

#[derive(Debug, thiserror::Error)]
#[error("duplicate nonce - already used")]
pub(crate) struct DuplicateNonce;

/// Tracks nonces seen by one node-local module instance.
///
/// Uses a [`moka::future::Cache`] with time-to-live expiration. Nonces are
/// automatically evicted after the configured maximum age. Clones of
/// [`NonceHistory`] share this same in-process cache, but other nodes and other
/// processes keep independent histories.
#[derive(Clone)]
pub(crate) struct NonceHistory {
    nonces: Cache<FieldElement, ()>,
}

impl NonceHistory {
    /// Initializes a new nonce history with automatic expiration.
    ///
    /// Nonces are automatically evicted after `max_nonce_age`. This only bounds
    /// how long the current node-local cache remembers a nonce; it does not
    /// create a threshold-wide "consumed nonce" record.
    ///
    /// # Arguments
    /// * `max_nonce_age` - Maximum age for nonces before they expire
    pub(crate) fn init(max_nonce_age: Duration) -> Self {
        ::metrics::gauge!(METRICS_ID_NODE_NONCE_HISTORY_SIZE).set(0.0);

        NonceHistory {
            nonces: Cache::builder().time_to_live(max_nonce_age).build(),
        }
    }

    /// Adds a nonce to the history.
    ///
    /// Returns an error if the nonce already exists in this local history,
    /// indicating a replay against this node/module instance.
    ///
    /// # Arguments
    /// * `nonce` - The nonce to track
    ///
    /// # Errors
    /// Returns [`DuplicateNonce`] if the nonce already exists in this local
    /// cache. That means the nonce was already seen by this node/module
    /// instance within `max_nonce_age`; it does not imply threshold-wide nonce
    /// consumption across other nodes or isolated replicas.
    pub(crate) async fn add_nonce(&self, nonce: FieldElement) -> Result<(), DuplicateNonce> {
        let entry = self.nonces.entry(nonce).or_insert_with(async {}).await;
        if !entry.is_fresh() {
            return Err(DuplicateNonce);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn test_nonce_history_duplicate_detection() {
        let mut rng = rand::thread_rng();
        let max_nonce_age = Duration::from_secs(60);
        let nonce_history = NonceHistory::init(max_nonce_age);

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
        let history1 = NonceHistory::init(max_nonce_age);
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
        let nonce_history = NonceHistory::init(max_nonce_age);

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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_nonce_insertion() {
        const TASKS: usize = 1000;

        let nonce = FieldElement::random(&mut rand::thread_rng());
        let history = NonceHistory::init(Duration::from_secs(60));

        // Barrier ensures all tasks attempt add_nonce as simultaneously as possible.
        let barrier = Arc::new(Barrier::new(TASKS));
        let mut join_set = tokio::task::JoinSet::new();

        for _ in 0..TASKS {
            let history = history.clone();
            let barrier = Arc::clone(&barrier);
            join_set.spawn(async move {
                barrier.wait().await;
                history.add_nonce(nonce).await
            });
        }

        let mut ok_count = 0usize;
        let mut err_count = 0usize;
        while let Some(result) = join_set.join_next().await {
            match result.expect("task did not panic") {
                Ok(()) => ok_count += 1,
                Err(DuplicateNonce) => err_count += 1,
            }
        }

        assert_eq!(ok_count, 1, "exactly one task should succeed");
        assert_eq!(
            err_count,
            TASKS - 1,
            "all other tasks should get DuplicateNonce"
        );
    }
}
