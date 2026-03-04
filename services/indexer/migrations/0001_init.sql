-- Initial schema for World ID Indexer
-- This migration creates the complete database schema

-- ============================================================================
-- Accounts table
-- ============================================================================
-- Stores World ID account state indexed by leaf_index
create table if not exists accounts (
    -- Leaf index in the Merkle tree (primary key)
    leaf_index bigint primary key,

    -- Recovery address for account recovery
    recovery_address bytea not null,

    -- Array of authenticator addresses (stored as JSON array of hex strings)
    authenticator_addresses jsonb not null default '[]',

    -- Array of authenticator public keys (stored as JSON array of hex strings)
    authenticator_pubkeys jsonb not null default '[]',

    -- Off-chain signer commitment (U256 stored as bytea)
    offchain_signer_commitment bytea not null,

    -- Latest event that modified this account (for rollback support)
    latest_block_number bigint not null,
    latest_log_index bigint not null,

    -- Timestamp for record keeping
    created_at timestamptz not null default now()
);

-- Index for rollback queries (find accounts modified after specific event)
create index if not exists idx_accounts_latest_event
    on accounts(latest_block_number, latest_log_index);

-- Index for time-based queries
create index if not exists idx_accounts_created_at
    on accounts(created_at);

-- Comments
comment on table accounts is
    'Stores World ID account state indexed by leaf position in the Merkle tree. Each account has a recovery address, authenticator keys, and off-chain signer commitment.';

comment on column accounts.leaf_index is
    'Position of this account in the Merkle tree (u64 stored as bigint)';

comment on column accounts.latest_block_number is
    'Block number of the last event that modified this account (used for rollback)';

comment on column accounts.latest_log_index is
    'Log index of the last event that modified this account (used for rollback)';

-- ============================================================================
-- World ID Registry Events table
-- ============================================================================
-- Stores complete event data to enable event replay for rollback functionality
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

-- Comments
comment on table world_id_registry_events is
    'Stores complete World ID Registry event data for event replay and rollback functionality. Each event contains full details including all parameters.';

comment on column world_id_registry_events.event_data is
    'JSONB column storing event-specific data. Structure varies by event_type: AccountCreated, AccountUpdated, AuthenticatorInserted, AuthenticatorRemoved, AccountRecovered, RootRecorded.';
