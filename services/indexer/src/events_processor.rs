use crate::{
    blockchain::{BlockchainEvent, RegistryEvent},
    db::{DBResult, PostgresDBTransaction},
};

pub struct EventsProcessor;

impl EventsProcessor {
    /// Process a single blockchain event and apply it to the database
    /// This method only handles applying the event to update account state.
    /// Event storage and idempotency checks are handled by the caller.
    pub async fn process_event(
        transaction: &mut PostgresDBTransaction<'_>,
        event: &BlockchainEvent<RegistryEvent>,
    ) -> DBResult<()> {
        // Apply the event to update account state
        match &event.details {
            RegistryEvent::AccountCreated(ev) => {
                transaction
                    .accounts()
                    .await?
                    .insert(
                        ev.leaf_index,
                        &ev.recovery_address,
                        &ev.authenticator_addresses,
                        &ev.authenticator_pubkeys,
                        &ev.offchain_signer_commitment,
                        event.block_number,
                        event.log_index,
                    )
                    .await?;
            }
            RegistryEvent::AccountUpdated(ev) => {
                transaction
                    .accounts()
                    .await?
                    .update_authenticator_at_index(
                        ev.leaf_index,
                        ev.pubkey_id,
                        &ev.new_authenticator_address,
                        &ev.new_authenticator_pubkey,
                        &ev.new_offchain_signer_commitment,
                        event.block_number,
                        event.log_index,
                    )
                    .await?;
            }
            RegistryEvent::AuthenticatorInserted(ev) => {
                transaction
                    .accounts()
                    .await?
                    .insert_authenticator_at_index(
                        ev.leaf_index,
                        ev.pubkey_id,
                        &ev.authenticator_address,
                        &ev.new_authenticator_pubkey,
                        &ev.new_offchain_signer_commitment,
                        event.block_number,
                        event.log_index,
                    )
                    .await?;
            }
            RegistryEvent::AuthenticatorRemoved(ev) => {
                transaction
                    .accounts()
                    .await?
                    .remove_authenticator_at_index(
                        ev.leaf_index,
                        ev.pubkey_id,
                        &ev.new_offchain_signer_commitment,
                        event.block_number,
                        event.log_index,
                    )
                    .await?;
            }
            RegistryEvent::AccountRecovered(ev) => {
                transaction
                    .accounts()
                    .await?
                    .reset_authenticator(
                        ev.leaf_index,
                        &ev.new_authenticator_address,
                        &ev.new_authenticator_pubkey,
                        &ev.new_offchain_signer_commitment,
                        event.block_number,
                        event.log_index,
                    )
                    .await?;
            }
            RegistryEvent::RootRecorded(_ev) => {}
        }

        Ok(())
    }
}
