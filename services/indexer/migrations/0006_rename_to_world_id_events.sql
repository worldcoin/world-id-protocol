-- Rename table to world_id_events
alter table account_created_events rename to world_id_events;

alter index if exists idx_commitment_updates_block to idx_world_id_events_block_number;
alter index if exists idx_commitment_updates_leaf to idx_world_id_events_leaf_index;
alter index if exists idx_commitment_updates_created_at to idx_world_id_events_created_at;
