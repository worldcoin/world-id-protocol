use alloy::primitives::U256;

use crate::{
    blockchain::{BlockchainEvent, RegistryEvent},
    db::{
        DB, DBResult, IsolationLevel, PostgresDBTransaction, WorldTreeEventType,
        WorldTreeRootEventType,
    },
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
    pub async fn handle_event(
        &mut self,
        event: BlockchainEvent<RegistryEvent>,
    ) -> DBResult<bool> {
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
            match &event.details {
                RegistryEvent::AccountCreated(ev) => {
                    let already_processed = Self::ensure_event_inserted(
                        &mut transaction,
                        &ev.leaf_index,
                        WorldTreeEventType::AccountCreated,
                        &ev.offchain_signer_commitment,
                        event.block_number,
                        &event.tx_hash,
                        event.log_index,
                    )
                    .await?;
                    if already_processed {
                        tracing::info!(?event, "skipping event as it was already processed");
                        continue;
                    }
                    transaction
                        .accounts()
                        .await?
                        .insert(
                            &ev.leaf_index,
                            &ev.recovery_address,
                            &ev.authenticator_addresses,
                            &ev.authenticator_pubkeys,
                            &ev.offchain_signer_commitment,
                        )
                        .await?;
                }
                RegistryEvent::AccountUpdated(ev) => {
                    let already_processed = Self::ensure_event_inserted(
                        &mut transaction,
                        &ev.leaf_index,
                        WorldTreeEventType::AccountUpdated,
                        &ev.new_offchain_signer_commitment,
                        event.block_number,
                        &event.tx_hash,
                        event.log_index,
                    )
                    .await?;
                    if already_processed {
                        tracing::info!(?event, "skipping event as it was already processed");
                        continue;
                    }
                    transaction
                        .accounts()
                        .await?
                        .update_authenticator_at_index(
                            &ev.leaf_index,
                            ev.pubkey_id,
                            &ev.new_authenticator_address,
                            &ev.new_authenticator_pubkey,
                            &ev.new_offchain_signer_commitment,
                        )
                        .await?;
                }
                RegistryEvent::AuthenticatorInserted(ev) => {
                    let already_processed = Self::ensure_event_inserted(
                        &mut transaction,
                        &ev.leaf_index,
                        WorldTreeEventType::AuthenticationInserted,
                        &ev.new_offchain_signer_commitment,
                        event.block_number,
                        &event.tx_hash,
                        event.log_index,
                    )
                    .await?;
                    if already_processed {
                        tracing::info!(?event, "skipping event as it was already processed");
                        continue;
                    }
                    transaction
                        .accounts()
                        .await?
                        .insert_authenticator_at_index(
                            &ev.leaf_index,
                            ev.pubkey_id,
                            &ev.authenticator_address,
                            &ev.new_authenticator_pubkey,
                            &ev.new_offchain_signer_commitment,
                        )
                        .await?;
                }
                RegistryEvent::AuthenticatorRemoved(ev) => {
                    let already_processed = Self::ensure_event_inserted(
                        &mut transaction,
                        &ev.leaf_index,
                        WorldTreeEventType::AuthenticationRemoved,
                        &ev.new_offchain_signer_commitment,
                        event.block_number,
                        &event.tx_hash,
                        event.log_index,
                    )
                    .await?;
                    if already_processed {
                        tracing::info!(?event, "skipping event as it was already processed");
                        continue;
                    }
                    transaction
                        .accounts()
                        .await?
                        .remove_authenticator_at_index(
                            &ev.leaf_index,
                            ev.pubkey_id,
                            &ev.new_offchain_signer_commitment,
                        )
                        .await?;
                }
                RegistryEvent::AccountRecovered(ev) => {
                    let already_processed = Self::ensure_event_inserted(
                        &mut transaction,
                        &ev.leaf_index,
                        WorldTreeEventType::AccountRecovered,
                        &ev.new_offchain_signer_commitment,
                        event.block_number,
                        &event.tx_hash,
                        event.log_index,
                    )
                    .await?;
                    if already_processed {
                        tracing::info!(?event, "skipping event as it was already processed");
                        continue;
                    }
                    transaction
                        .accounts()
                        .await?
                        .reset_authenticator(
                            &ev.leaf_index,
                            &ev.new_authenticator_address,
                            &ev.new_authenticator_pubkey,
                            &ev.new_offchain_signer_commitment,
                        )
                        .await?;
                }
                RegistryEvent::RootRecorded(ev) => {
                    let already_processed = Self::ensure_root_inserted(
                        &mut transaction,
                        event.block_number,
                        event.log_index,
                        WorldTreeRootEventType::RootRecorded,
                        &event.tx_hash,
                        &ev.root,
                        &ev.timestamp,
                    )
                    .await?;
                    if already_processed {
                        tracing::info!(?event, "skipping event as it was already processed");
                        continue;
                    }
                }
            }
        }

        transaction.commit().await?;

        self.buffered_events.clear();

        Ok(())
    }

    // Returned bool indicates if event was already added to database
    // and processed.
    async fn ensure_event_inserted(
        transaction: &mut PostgresDBTransaction<'_>,
        leaf_index: &U256,
        event_type: WorldTreeEventType,
        offchain_signer_commitment: &U256,
        block_number: u64,
        tx_hash: &U256,
        log_index: u64,
    ) -> DBResult<bool> {
        // Check if we have same record in database first
        let db_event = transaction
            .world_tree_events()
            .await?
            .get_event((block_number, log_index))
            .await?;

        if let Some(db_event) = db_event
            && db_event.id.block_number == block_number
            && db_event.id.log_index == log_index
            && db_event.event_type == event_type
            && db_event.leaf_index == *leaf_index
            && db_event.tx_hash == *tx_hash
            && db_event.offchain_signer_commitment == *offchain_signer_commitment
        {
            return Ok(true);
        }

        transaction
            .world_tree_events()
            .await?
            .insert_event(
                leaf_index,
                event_type,
                offchain_signer_commitment,
                block_number,
                tx_hash,
                log_index,
            )
            .await?;

        Ok(false)
    }

    // Returned bool indicates if event was already added to database
    // and processed.
    async fn ensure_root_inserted(
        transaction: &mut PostgresDBTransaction<'_>,
        block_number: u64,
        log_index: u64,
        event_type: WorldTreeRootEventType,
        tx_hash: &U256,
        root: &U256,
        timestamp: &U256,
    ) -> DBResult<bool> {
        // Check if we have same record in database first
        let db_event = transaction
            .world_tree_roots()
            .await?
            .get_root((block_number, log_index))
            .await?;

        if let Some(db_event) = db_event
            && db_event.id.block_number == block_number
            && db_event.id.log_index == log_index
            && db_event.event_type == event_type
            && db_event.tx_hash == *tx_hash
            && db_event.root == *root
            && db_event.timestamp == *timestamp
        {
            return Ok(true);
        }

        transaction
            .world_tree_roots()
            .await?
            .insert_event(
                block_number,
                log_index,
                event_type,
                tx_hash,
                root,
                timestamp,
            )
            .await?;

        Ok(false)
    }
}
