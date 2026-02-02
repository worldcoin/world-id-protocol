-- Drop the unique constraint on root column in world_tree_roots table
-- This allows the same root to exist at different (block_number, log_index) positions
alter table world_tree_roots drop constraint if exists world_tree_roots_root_key;
