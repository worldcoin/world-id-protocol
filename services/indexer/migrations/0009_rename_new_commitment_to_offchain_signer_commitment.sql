-- Rename new_commitment column to offchain_signer_commitment in world_id_events table
alter table world_id_events rename column new_commitment to offchain_signer_commitment;
