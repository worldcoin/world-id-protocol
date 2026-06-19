-- Drop unused indexes on world_id_registry_events that slow down inserts.
--
-- The GIN index on event_data is the primary culprit: it decomposes the entire
-- JSONB document on every insert. The root lookup query uses the targeted partial
-- expression index (idx_world_id_registry_events_root) instead, so the full GIN
-- index is never consulted.
--
-- The remaining three are maintained on every insert but match no query in the
-- codebase: block_hash is covered by the compound block_number_hash index;
-- tx_hash and created_at appear only in SELECT lists, never in WHERE clauses.
DROP INDEX IF EXISTS idx_world_id_registry_events_event_data;
DROP INDEX IF EXISTS idx_world_id_registry_events_created_at;
DROP INDEX IF EXISTS idx_world_id_registry_events_block_hash;
DROP INDEX IF EXISTS idx_world_id_registry_events_tx_hash;
