-- Reader-facing Merkle tree sync journal.
--
-- The deployed database already contains account and registry event state, so
-- this migration creates the journal and seeds it with the current canonical
-- leaf state plus a root checkpoint.
--
-- IMPORTANT: Run this migration only once on existing deployments.

create table if not exists sync_batch (
    batch_id bigserial primary key,
    kind varchar(16) not null,
    expected_root bytea not null,
    next_leaf_index bigint not null,
    block_number bigint not null,
    log_index bigint not null,
    onchain_timestamp bigint not null,
    created_at timestamptz not null default now()
);

create index if not exists idx_sync_batch_block_log
    on sync_batch(block_number, log_index);

create table if not exists sync_leaf_change (
    change_id bigserial primary key,
    batch_id bigint not null references sync_batch(batch_id) on delete cascade,
    leaf_index bigint not null,
    commitment bytea,
    created_at timestamptz not null default now()
);

create index if not exists idx_sync_leaf_change_batch
    on sync_leaf_change(batch_id, change_id);

create index if not exists idx_sync_leaf_change_leaf
    on sync_leaf_change(leaf_index, batch_id, change_id);

-- Baseline checkpoint from the latest on-chain root. Leaf changes are seeded
-- separately once the bootstrap batch row exists.
with latest_root_event as (
    select
        block_number,
        log_index,
        event_data->>'root' as root,
        (event_data->>'timestamp')::bigint as onchain_timestamp
    from world_id_registry_events
    where event_type = 'root_recorded'
    order by block_number desc, log_index desc
    limit 1
),
account_state as (
    select coalesce(max(leaf_index) + 1, 1) as next_leaf_index
    from accounts
)
insert into sync_batch (
    kind,
    expected_root,
    next_leaf_index,
    block_number,
    log_index,
    onchain_timestamp
)
select
    'forward',
    decode(lpad(substr(latest_root_event.root, 3), 64, '0'), 'hex'),
    account_state.next_leaf_index,
    latest_root_event.block_number,
    latest_root_event.log_index,
    latest_root_event.onchain_timestamp
from latest_root_event
cross join account_state
where not exists (select 1 from sync_batch);

-- Baseline leaf state for existing deployments. Future rows are appended by
-- the writer in the same transaction as the account/registry projections.
insert into sync_leaf_change (batch_id, leaf_index, commitment)
select
    (select batch_id from sync_batch order by batch_id desc limit 1),
    leaf_index,
    offchain_signer_commitment
from accounts
where exists (select 1 from sync_batch)
  and not exists (select 1 from sync_leaf_change);
