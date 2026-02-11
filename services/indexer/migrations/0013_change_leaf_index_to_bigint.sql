-- Change leaf_index from bytea (U256) to bigint (u64) in accounts table
-- This migration assumes all existing leaf_index values fit within u64 range
alter table accounts alter column leaf_index type bigint using (
    -- Convert bytea to bigint by interpreting as big-endian unsigned integer
    -- Take only the last 8 bytes (rightmost) as this is where u64 values are stored
    -- in U256 representation
    ('x' || encode(substring(leaf_index from length(leaf_index) - 7 for 8), 'hex'))::bit(64)::bigint
);

-- Change leaf_index from bytea (U256) to bigint (u64) in world_tree_events table
alter table world_tree_events alter column leaf_index type bigint using (
    -- Convert bytea to bigint by interpreting as big-endian unsigned integer
    -- Take only the last 8 bytes (rightmost) as this is where u64 values are stored
    -- in U256 representation
    ('x' || encode(substring(leaf_index from length(leaf_index) - 7 for 8), 'hex'))::bit(64)::bigint
);
