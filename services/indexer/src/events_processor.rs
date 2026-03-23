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
            RegistryEvent::RecoveryAgentUpdateInitiated(ev) => {
                // Convert U256 execute_after (unix timestamp) to u64
                let execute_after_unix: u64 = ev.execute_after.try_into().unwrap_or(u64::MAX);
                transaction
                    .pending_recovery_agent_updates()
                    .await?
                    .upsert_pending(ev.leaf_index, &ev.new_recovery_agent, execute_after_unix)
                    .await?;
            }
            RegistryEvent::RecoveryAgentUpdateExecuted(ev) => {
                // Mark the pending update as executed
                transaction
                    .pending_recovery_agent_updates()
                    .await?
                    .mark_executed(ev.leaf_index)
                    .await?;
                // Update the recovery agent on the account record
                transaction
                    .accounts()
                    .await?
                    .update_recovery_address(ev.leaf_index, &ev.new_recovery_agent)
                    .await?;
            }
            RegistryEvent::RecoveryAgentUpdateCancelled(ev) => {
                transaction
                    .pending_recovery_agent_updates()
                    .await?
                    .mark_cancelled(ev.leaf_index)
                    .await?;
            }
        }

        Ok(())
    }
}
