-- Rename table to world_id_events
alter table if exists commitment_update_events rename to world_id_events;

alter index if exists idx_commitment_updates_block rename to idx_world_id_events_block_number;
alter index if exists idx_commitment_updates_leaf rename to idx_world_id_events_leaf_index;
alter index if exists idx_commitment_updates_created_at rename to idx_world_id_events_created_at;
