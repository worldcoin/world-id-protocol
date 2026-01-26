-- Change accounts table column types
alter table accounts alter column recovery_address type bytea using decode(recovery_address, 'hex');
alter table accounts alter column offchain_signer_commitment type bytea using decode(offchain_signer_commitment, 'hex');
alter table accounts alter column authenticator_addresses set default '[]';
alter table accounts alter column leaf_index type bytea using decode(leaf_index, 'hex');

-- Change world_id_events table column types
alter table world_id_events alter column event_type type varchar(50);
alter table world_id_events alter column new_commitment type bytea using decode(new_commitment, 'hex');
alter table world_id_events alter column tx_hash type bytea using decode(tx_hash, 'hex');
alter table world_id_events alter column leaf_index type bytea using decode(leaf_index, 'hex');

-- Drop the existing primary key and id column from world_id_events
alter table world_id_events drop constraint commitment_update_events_pkey;
alter table world_id_events drop column id;

-- Create compound primary key on (block_number, log_index)
alter table world_id_events add primary key (block_number, log_index);
