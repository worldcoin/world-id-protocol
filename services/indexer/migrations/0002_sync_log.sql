-- Reader-facing Merkle tree sync journal.
--
-- The deployed database already contains account and registry event state, so
-- this migration creates the journal and seeds it with the current canonical
-- leaf state plus a root checkpoint.
create table if not exists sync_log (
    sync_id bigserial primary key,
    kind varchar(32) not null,
    leaf_index bigint,
    commitment bytea,
    expected_root bytea,
    next_leaf_index bigint,
    created_at timestamptz not null default now()
);

create index if not exists idx_sync_log_kind_sync_id
    on sync_log(kind, sync_id);

create index if not exists idx_sync_log_leaf_sync_id
    on sync_log(leaf_index, sync_id)
    where leaf_index is not null;

-- Baseline leaf state for existing deployments. Future rows are appended by
-- the writer in the same transaction as the account/registry projections.
insert into sync_log (kind, leaf_index, commitment)
select
    'leaf_update',
    leaf_index,
    offchain_signer_commitment
from accounts
where not exists (select 1 from sync_log)
order by leaf_index asc;

-- Baseline checkpoint. Roots are serialized into event_data as 0x-prefixed hex
-- strings, while U256 columns are stored as bytea.
with latest_root as (
    select event_data->>'root' as root
    from world_id_registry_events
    where event_type = 'root_recorded'
    order by block_number desc, log_index desc
    limit 1
),
account_state as (
    select coalesce(max(leaf_index) + 1, 1) as next_leaf_index
    from accounts
)
insert into sync_log (kind, expected_root, next_leaf_index)
select
    'root_verification',
    decode(lpad(substr(latest_root.root, 3), 64, '0'), 'hex'),
    account_state.next_leaf_index
from latest_root
cross join account_state
where not exists (
    select 1
    from sync_log
    where kind = 'root_verification'
);
