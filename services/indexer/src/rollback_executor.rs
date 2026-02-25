use crate::{
    db::{DBResult, PostgresDBTransaction, WorldIdRegistryEventId},
    events_processor::EventsProcessor,
};

pub struct RollbackExecutor<'a, 'b> {
    tx: &'a mut PostgresDBTransaction<'b>,
}

impl<'a, 'b> RollbackExecutor<'a, 'b> {
    pub fn new(tx: &'a mut PostgresDBTransaction<'b>) -> Self {
        Self { tx }
    }

    pub async fn rollback_to_event<T: Into<WorldIdRegistryEventId>>(
        &mut self,
        event_id: T,
    ) -> DBResult<()> {
        let event_id: WorldIdRegistryEventId = event_id.into();
        tracing::info!("rolling back up to event = {:?}", event_id);

        // Step 1: Get leaf indices where latest event is after rollback point
        let affected_leaf_indices = self
            .tx
            .accounts()
            .await?
            .get_after_event((event_id.block_number, event_id.log_index))
            .await?;

        tracing::info!("Found {} accounts to rollback", affected_leaf_indices.len());

        // Step 2: Remove those accounts
        let removed_accounts = self
            .tx
            .accounts()
            .await?
            .delete_after_event((event_id.block_number, event_id.log_index))
            .await?;

        tracing::info!("Removed {} accounts", removed_accounts);

        // Step 3: Remove world_id_registry_events greater than event_id
        let removed_registry_events = self
            .tx
            .world_id_registry_events()
            .await?
            .delete_after_event(&event_id)
            .await?;

        tracing::info!("Removed {} registry events", removed_registry_events);

        // Step 4: Replay events for each affected leaf index
        for leaf_index in affected_leaf_indices {
            self.replay_events_for_leaf(leaf_index, &event_id).await?;
        }

        tracing::info!("Rollback completed successfully");

        Ok(())
    }

    /// Replay all events for a specific leaf index up to the rollback point
    async fn replay_events_for_leaf(
        &mut self,
        leaf_index: u64,
        event_id: &WorldIdRegistryEventId,
    ) -> DBResult<()> {
        // Get all events for this leaf up to the rollback point from the full events table
        let events = self
            .tx
            .world_id_registry_events()
            .await?
            .get_events_for_leaf(leaf_index, event_id)
            .await?;

        tracing::info!(
            "Replaying {} events for leaf_index {}",
            events.len(),
            leaf_index
        );

        for (i, event) in events.iter().enumerate() {
            tracing::info!(
                "  Event {}: block={}, log={}, type={:?}",
                i,
                event.block_number,
                event.log_index,
                event.details
            );
        }

        // Apply each event in order
        for event in events {
            EventsProcessor::process_event(self.tx, &event).await?;
        }

        Ok(())
    }
}
