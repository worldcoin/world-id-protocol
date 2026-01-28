-- Drop the unique constraint on (tx_hash, log_index)
-- This constraint was originally created in migration 0002 on commitment_update_events table
-- The table was renamed to world_id_events in migration 0006, but constraint name remains from original table
alter table world_id_events drop constraint if exists commitment_update_events_tx_hash_log_index_key;

-- Rename table to world_id_events
alter table if exists world_id_events rename to world_tree_events;

alter index if exists idx_world_id_events_block_number rename to idx_world_tree_events_block_number;
alter index if exists idx_world_id_events_leaf_index rename to idx_world_tree_events_leaf_index;
alter index if exists idx_world_id_events_created_at rename to idx_world_tree_events_created_at;
