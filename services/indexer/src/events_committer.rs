use crate::{
    blockchain::{BlockchainEvent, RegistryEvent},
    db::{DB, DBResult, IsolationLevel},
    events_processor::EventsProcessor,
};

pub struct EventsCommitter<'a> {
    db: &'a DB,
    buffered_events: Vec<BlockchainEvent<RegistryEvent>>,
}

impl<'a> EventsCommitter<'a> {
    pub fn new(db: &'a DB) -> Self {
        Self {
            db,
            buffered_events: vec![],
        }
    }
    /// Handle a single event: buffer it, and commit when a RootRecorded event
    /// is seen. Returns `true` when a DB commit happened (batch flushed).
    pub async fn handle_event(&mut self, event: BlockchainEvent<RegistryEvent>) -> DBResult<bool> {
        let is_root = matches!(event.details, RegistryEvent::RootRecorded(_));
        self.buffer_event(event)?;

        if is_root {
            self.commit_events().await?;
            return Ok(true);
        }

        Ok(false)
    }

    fn buffer_event(&mut self, event: BlockchainEvent<RegistryEvent>) -> DBResult<()> {
        tracing::info!(?event, "buffering event");
        self.buffered_events.push(event);
        Ok(())
    }

    async fn commit_events(&mut self) -> DBResult<()> {
        tracing::info!("committing events to DB");

        let mut transaction = self.db.transaction(IsolationLevel::Serializable).await?;

        for event in self.buffered_events.iter() {
            // First, store the full event in world_id_registry_events with idempotency check
            let exists = transaction
                .world_id_registry_events()
                .await?
                .check_event_exists(event.block_number, event.log_index, &event.tx_hash)
                .await?;

            match exists {
                Some(true) => {
                    // Event already processed with matching tx_hash - skip it (idempotent)
                    tracing::info!(
                        block_number = event.block_number,
                        log_index = event.log_index,
                        "Event already processed, skipping"
                    );
                    continue;
                }
                Some(false) => {
                    // Event exists but tx_hash differs - this is a reorg!
                    return Err(crate::db::DBError::InvalidEventType(format!(
                        "Event at block {} log_index {} exists with different tx_hash - possible reorg detected",
                        event.block_number, event.log_index
                    )));
                }
                None => {
                    // Event doesn't exist - insert it
                    transaction
                        .world_id_registry_events()
                        .await?
                        .insert_event(event)
                        .await?;
                }
            }

            // Apply the event to update account state
            EventsProcessor::process_event(&mut transaction, event).await?;
        }

        transaction.commit().await?;

        self.buffered_events.clear();

        Ok(())
    }
}
