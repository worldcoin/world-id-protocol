-- Rename account_index to leaf_index in accounts table
alter table accounts rename column account_index to leaf_index;

-- Rename account_index to leaf_index in commitment_update_events table
alter table commitment_update_events rename column account_index to leaf_index;

-- Drop old index and create new index on commitment_update_events
drop index if exists idx_commitment_updates_account;
create index if not exists idx_commitment_updates_leaf on commitment_update_events(leaf_index);
