-- Add latest event tracking to accounts table
-- This allows efficient rollback by identifying which accounts were modified after a specific event

-- First add columns as nullable
alter table accounts add column latest_block_number bigint;
alter table accounts add column latest_log_index bigint;

-- Populate with the latest event from world_tree_events for each account
update accounts
set latest_block_number = subquery.block_number,
    latest_log_index = subquery.log_index
from (
    select
        leaf_index,
        block_number,
        log_index
    from world_tree_events wte1
    where (block_number, log_index) = (
        select block_number, log_index
        from world_tree_events wte2
        where wte2.leaf_index = wte1.leaf_index
        order by block_number desc, log_index desc
        limit 1
    )
) as subquery
where accounts.leaf_index = subquery.leaf_index;

-- Now make them NOT NULL
alter table accounts alter column latest_block_number set not null;
alter table accounts alter column latest_log_index set not null;

-- Create index for rollback queries (find accounts modified after specific event)
create index if not exists idx_accounts_latest_event
    on accounts(latest_block_number, latest_log_index);
