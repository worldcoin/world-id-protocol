-- Pending recovery agent updates table
-- Tracks initiated recovery agent updates and their execution status

create table if not exists pending_recovery_agent_updates (
    -- Leaf index in the Merkle tree (primary key, one pending update per account)
    leaf_index bigint primary key,

    -- The new recovery agent address (stored as bytea, same as accounts.recovery_address)
    new_recovery_agent bytea not null,

    -- When the update can be executed (after cooldown elapses)
    execute_after timestamptz not null,

    -- Current status of the update
    status varchar(20) not null default 'pending'
        check (status in ('pending', 'executed', 'cancelled')),

    -- Number of on-chain execution attempts
    attempts integer not null default 0,

    -- Timestamp of last execution attempt
    last_attempt_at timestamptz,

    -- Timestamp for record keeping
    created_at timestamptz not null default now(),

    -- Timestamp of last status change
    updated_at timestamptz not null default now()
);

-- Index for the scheduler query: find pending updates ready for execution
create index if not exists idx_pending_recovery_agent_updates_pending_ready
    on pending_recovery_agent_updates(execute_after)
    where status = 'pending';

-- Comments
comment on table pending_recovery_agent_updates is
    'Tracks pending recovery agent updates from RecoveryAgentUpdateInitiated events. The scheduler polls for ready rows and calls executeRecoveryAgentUpdate on-chain.';

comment on column pending_recovery_agent_updates.leaf_index is
    'Position of the account in the Merkle tree (u64 stored as bigint)';

comment on column pending_recovery_agent_updates.status is
    'pending = awaiting execution, executed = on-chain execution confirmed, cancelled = update was cancelled';
