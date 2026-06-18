-- !no-transaction
-- Partial expression index for root lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_world_id_registry_events_root
    ON world_id_registry_events ((event_data->>'root'))
    WHERE event_type = 'root_recorded';

-- Compound index for reorg detection (block_number, block_hash)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_world_id_registry_events_block_number_hash
    ON world_id_registry_events (block_number, block_hash);
