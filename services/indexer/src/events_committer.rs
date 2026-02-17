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
            EventsProcessor::process_event(&mut transaction, event).await?;
        }

        transaction.commit().await?;

        self.buffered_events.clear();

        Ok(())
    }
}
