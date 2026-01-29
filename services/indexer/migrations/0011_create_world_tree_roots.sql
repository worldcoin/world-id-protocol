-- Create world_tree_roots table to track historical tree root states
create table if not exists world_tree_roots (
    block_number bigint not null,
    log_index bigint not null,
    tx_hash bytea not null,
    event_type varchar(50) not null,
    root bytea not null unique,
    root_timestamp bytea not null,
    created_at timestamptz not null default now(),
    primary key (block_number, log_index)
);

-- Add index on root_timestamp for efficient time-based queries
create index if not exists idx_world_tree_roots_root_timestamp on world_tree_roots(root_timestamp desc);

-- Add index on created_at for efficient polling queries
create index if not exists idx_world_tree_roots_created_at on world_tree_roots(created_at desc);
