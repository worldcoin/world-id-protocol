use crate::{
    blockchain::{BlockchainEvent, RegistryEvent},
    db::{DB, IsolationLevel, WorldTreeEventType, WorldTreeRootEventType},
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
    pub async fn handle_event(
        &mut self,
        event: BlockchainEvent<RegistryEvent>,
    ) -> anyhow::Result<()> {
        match event.details {
            RegistryEvent::AccountCreated(_) => self.buffer_event(event).await,
            RegistryEvent::AccountUpdated(_) => self.buffer_event(event).await,
            RegistryEvent::AuthenticatorInserted(_) => self.buffer_event(event).await,
            RegistryEvent::AuthenticatorRemoved(_) => self.buffer_event(event).await,
            RegistryEvent::AccountRecovered(_) => self.buffer_event(event).await,
            RegistryEvent::RootRecorded(_) => {
                self.buffer_event(event).await?;
                self.commit_events().await?;
                Ok(())
            }
        }
    }

    async fn buffer_event(&mut self, event: BlockchainEvent<RegistryEvent>) -> anyhow::Result<()> {
        tracing::info!(?event, "buffering event");
        self.buffered_events.push(event);
        Ok(())
    }

    async fn commit_events(&mut self) -> anyhow::Result<()> {
        tracing::info!("committing events to DB");

        let events: Vec<BlockchainEvent<RegistryEvent>> = self.buffered_events.drain(0..).collect();

        let mut transaction = self.db.transaction(IsolationLevel::Serializable).await?;

        for event in events.iter() {
            match &event.details {
                RegistryEvent::AccountCreated(ev) => {
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
                    transaction
                        .world_tree_events()
                        .await?
                        .insert_event(
                            &ev.leaf_index,
                            WorldTreeEventType::AccountCreated,
                            &ev.offchain_signer_commitment,
                            event.block_number,
                            &event.tx_hash,
                            event.log_index,
                        )
                        .await?;
                }
                RegistryEvent::AccountUpdated(ev) => {
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
                    transaction
                        .world_tree_events()
                        .await?
                        .insert_event(
                            &ev.leaf_index,
                            WorldTreeEventType::AccountUpdated,
                            &ev.new_offchain_signer_commitment,
                            event.block_number,
                            &event.tx_hash,
                            event.log_index,
                        )
                        .await?;
                }
                RegistryEvent::AuthenticatorInserted(ev) => {
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
                    transaction
                        .world_tree_events()
                        .await?
                        .insert_event(
                            &ev.leaf_index,
                            WorldTreeEventType::AuthenticationInserted,
                            &ev.new_offchain_signer_commitment,
                            event.block_number,
                            &event.tx_hash,
                            event.log_index,
                        )
                        .await?;
                }
                RegistryEvent::AuthenticatorRemoved(ev) => {
                    transaction
                        .accounts()
                        .await?
                        .remove_authenticator_at_index(
                            &ev.leaf_index,
                            ev.pubkey_id,
                            &ev.new_offchain_signer_commitment,
                        )
                        .await?;
                    transaction
                        .world_tree_events()
                        .await?
                        .insert_event(
                            &ev.leaf_index,
                            WorldTreeEventType::AuthenticationRemoved,
                            &ev.new_offchain_signer_commitment,
                            event.block_number,
                            &event.tx_hash,
                            event.log_index,
                        )
                        .await?;
                }
                RegistryEvent::AccountRecovered(ev) => {
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
                    transaction
                        .world_tree_events()
                        .await?
                        .insert_event(
                            &ev.leaf_index,
                            WorldTreeEventType::AccountRecovered,
                            &ev.new_offchain_signer_commitment,
                            event.block_number,
                            &event.tx_hash,
                            event.log_index,
                        )
                        .await?;
                }
                RegistryEvent::RootRecorded(ev) => {
                    transaction
                        .world_tree_roots()
                        .await?
                        .insert_event(
                            event.block_number,
                            event.log_index,
                            WorldTreeRootEventType::RootRecorded,
                            &event.tx_hash,
                            &ev.root,
                            &ev.timestamp,
                        )
                        .await?;
                }
            }
        }

        transaction.commit().await?;

        Ok(())
    }
}
