-- WIP-107 Billing Contract: `BilledRpUpdated` events and sync progress.
--
-- Events are append-only; an RP's status is its latest event. A reorganization deletes the
-- events above the rewind point, which restores the previous status.

create table if not exists billed_rp_events (
    -- The Billing Contract that emitted the event.
    billing_contract bytea not null,
    block_number bigint not null,
    log_index bigint not null,
    block_hash bytea not null,
    tx_hash bytea not null,
    -- The RP's `uint64` id, 8 bytes big-endian.
    rp_id bytea not null,
    billed boolean not null,
    primary key (billing_contract, block_number, log_index)
);

create index if not exists idx_billed_rp_events_latest
    on billed_rp_events (billing_contract, rp_id, block_number desc, log_index desc);

-- The last block synced per Billing Contract, with its hash to detect reorganizations.
create table if not exists billing_sync_checkpoints (
    billing_contract bytea primary key,
    block_number bigint not null,
    block_hash bytea not null
);
