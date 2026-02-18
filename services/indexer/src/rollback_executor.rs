use crate::db::{
    DB, DBResult, IsolationLevel, PostgresDBTransaction, WorldTreeEvent, WorldTreeEventId,
};

pub struct RollbackExecutor<'a> {
    db: &'a DB,
}

impl<'a> RollbackExecutor<'a> {
    pub fn new(db: &'a DB) -> Self {
        Self { db }
    }

    pub async fn rollback_to_event(&mut self, event_id: WorldTreeEventId) -> DBResult<()> {
        tracing::info!("rolling back up to event = {:?}", event_id);

        let mut transaction = self.db.transaction(IsolationLevel::Serializable).await?;

        // Step 1: Get leaf indices where latest event is after rollback point
        let affected_leaf_indices = transaction
            .accounts()
            .await?
            .get_affected_leaf_indices(&event_id)
            .await?;

        tracing::info!("Found {} accounts to rollback", affected_leaf_indices.len());

        // Step 2: Remove those accounts
        let removed_accounts = transaction
            .accounts()
            .await?
            .delete_after_event(&event_id)
            .await?;

        tracing::info!("Removed {} accounts", removed_accounts);

        // Step 3: Remove world_tree_events greater than event_id
        let removed_events = transaction
            .world_tree_events()
            .await?
            .delete_after_event(&event_id)
            .await?;

        tracing::info!("Removed {} events", removed_events);

        // Step 4: Remove world_tree_roots greater than event_id
        let removed_roots = transaction
            .world_tree_roots()
            .await?
            .delete_after_event(&event_id)
            .await?;

        tracing::info!("Removed {} roots", removed_roots);

        // Step 5: Replay events for each affected leaf index
        for leaf_index in affected_leaf_indices {
            self.replay_events_for_leaf(&mut transaction, leaf_index, &event_id)
                .await?;
        }

        transaction.commit().await?;

        tracing::info!("Rollback completed successfully");

        Ok(())
    }

    /// Replay all events for a specific leaf index up to the rollback point
    async fn replay_events_for_leaf(
        &self,
        tx: &mut PostgresDBTransaction<'_>,
        leaf_index: u64,
        event_id: &WorldTreeEventId,
    ) -> DBResult<()> {
        // Get all events for this leaf up to the rollback point
        let events = tx
            .world_tree_events()
            .await?
            .get_events_for_leaf(leaf_index, event_id)
            .await?;

        tracing::debug!(
            "Replaying {} events for leaf_index {}",
            events.len(),
            leaf_index
        );

        // Apply each event in order
        for event in events {
            EventsProcessor::process_event(&mut tx, event).await?;
        }

        Ok(())
    }
}
