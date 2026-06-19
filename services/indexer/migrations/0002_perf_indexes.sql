-- Performance indexes for World ID Registry Events
-- This migration adds targeted indexes and removes unused ones that slow down inserts

-- ============================================================================
-- New performance indexes
-- ============================================================================

-- Partial expression index for root lookup (replaces full GIN scan for root queries)
create index if not exists idx_world_id_registry_events_root
    on world_id_registry_events ((event_data->>'root'))
    where event_type = 'root_recorded';

-- Compound index for reorg detection (block_number, block_hash)
create index if not exists idx_world_id_registry_events_block_number_hash
    on world_id_registry_events (block_number, block_hash);

-- ============================================================================
-- Drop unused indexes
-- ============================================================================
-- The GIN index on event_data is the primary culprit: it decomposes the entire
-- JSONB document on every insert. The root lookup query uses the targeted partial
-- expression index (idx_world_id_registry_events_root) instead, so the full GIN
-- index is never consulted.
--
-- The remaining three are maintained on every insert but match no query in the
-- codebase: block_hash is covered by the compound block_number_hash index;
-- tx_hash and created_at appear only in SELECT lists, never in WHERE clauses.
drop index if exists idx_world_id_registry_events_event_data;
drop index if exists idx_world_id_registry_events_created_at;
drop index if exists idx_world_id_registry_events_block_hash;
drop index if exists idx_world_id_registry_events_tx_hash;
