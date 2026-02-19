-- Create table for storing full World ID Registry events
-- This table stores complete event data to enable event replay for rollback functionality

create table if not exists world_id_registry_events (
    -- Event identifier (compound primary key)
    block_number bigint not null,
    log_index bigint not null,

    -- Block metadata
    block_hash bytea not null,

    -- Transaction metadata
    tx_hash bytea not null,

    -- Event classification
    event_type varchar(50) not null,

    -- Optional leaf index (NULL for RootRecorded events)
    leaf_index bigint,

    -- Full event data as JSONB for flexibility and queryability
    event_data jsonb not null,

    -- Timestamp for record keeping
    created_at timestamptz not null default now(),

    -- Primary key on (block_number, log_index) for efficient querying and uniqueness
    primary key (block_number, log_index)
);

-- Index for querying events by leaf_index (for account-specific queries)
create index idx_world_id_registry_events_leaf_index
    on world_id_registry_events(leaf_index)
    where leaf_index is not null;

-- Index for querying by event type
create index idx_world_id_registry_events_event_type
    on world_id_registry_events(event_type);

-- GIN index for efficient JSONB queries (allows querying within event_data)
create index idx_world_id_registry_events_event_data
    on world_id_registry_events using gin (event_data);

-- Index for time-based queries
create index idx_world_id_registry_events_created_at
    on world_id_registry_events(created_at);

-- Index for block lookup
create index idx_world_id_registry_events_block_hash
    on world_id_registry_events(block_hash);

-- Index for transaction lookup
create index idx_world_id_registry_events_tx_hash
    on world_id_registry_events(tx_hash);

-- Comment on the table
comment on table world_id_registry_events is
    'Stores complete World ID Registry event data for event replay and rollback functionality. Each event contains full details including all parameters.';

comment on column world_id_registry_events.event_data is
    'JSONB column storing event-specific data. Structure varies by event_type: AccountCreated, AccountUpdated, AuthenticatorInserted, AuthenticatorRemoved, AccountRecovered, RootRecorded.';
