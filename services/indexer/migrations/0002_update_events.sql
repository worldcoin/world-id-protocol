-- Add table for tracking all commitment update events
create table if not exists commitment_update_events (
    id bigserial primary key,
    account_index text not null,
    event_type text not null, -- 'created', 'updated', 'inserted', 'removed', 'recovered'
    new_commitment text not null,
    block_number bigint not null,
    tx_hash text not null,
    log_index bigint not null,
    created_at timestamptz not null default now(),
    unique(tx_hash, log_index)
);

-- Add index for querying by account
create index if not exists idx_commitment_updates_account on commitment_update_events(account_index);
create index if not exists idx_commitment_updates_block on commitment_update_events(block_number);

