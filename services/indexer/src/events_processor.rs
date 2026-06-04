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
                        ev.leafIndex,
                        &ev.recoveryAddress,
                        &ev.authenticatorAddresses,
                        &ev.authenticatorPubkeys,
                        &ev.offchainSignerCommitment,
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
                        ev.leafIndex,
                        ev.pubkeyId,
                        &ev.newAuthenticatorAddress,
                        &ev.newAuthenticatorPubkey,
                        &ev.newOffchainSignerCommitment,
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
                        ev.leafIndex,
                        ev.pubkeyId,
                        &ev.authenticatorAddress,
                        &ev.newAuthenticatorPubkey,
                        &ev.newOffchainSignerCommitment,
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
                        ev.leafIndex,
                        ev.pubkeyId,
                        &ev.newOffchainSignerCommitment,
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
                        ev.leafIndex,
                        &ev.newAuthenticatorAddress,
                        &ev.newAuthenticatorPubkey,
                        &ev.newOffchainSignerCommitment,
                        event.block_number,
                        event.log_index,
                    )
                    .await?;
            }
            RegistryEvent::RootRecorded(_ev) => {}
            // Other registry events (ownership, fee, recovery-agent, etc.) are
            // not indexed and are never fetched by the log filter.
            _ => {}
        }

        Ok(())
    }
}
