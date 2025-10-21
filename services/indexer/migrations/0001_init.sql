-- Create checkpoints table for resume support
create table if not exists checkpoints (
    name text primary key,
    last_block bigint not null
);

-- AccountCreated index table
create table if not exists account_created_events (
    account_index text primary key,
    recovery_address text not null,
    authenticator_addresses jsonb not null,
    offchain_signer_commitment text not null,
    created_at timestamptz not null default now()
);
