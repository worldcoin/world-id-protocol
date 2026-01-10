-- Add last_updated_block column to accounts table
alter table accounts add column last_updated_block bigint;

-- Set initial value for existing rows (use 0 as default for existing accounts)
update accounts set last_updated_block = 0 where last_updated_block is null;

-- Make it NOT NULL after setting defaults
alter table accounts alter column last_updated_block set not null;

-- Create trigger function to enforce that last_updated_block must increase
create or replace function check_last_updated_block_increment()
returns trigger as $$
begin
    -- Ensure new value is greater than old value
    if NEW.last_updated_block <= OLD.last_updated_block then
        raise exception 'last_updated_block must be incremented. Current: %, Attempted: %', 
            OLD.last_updated_block, NEW.last_updated_block;
    end if;
    return NEW;
end;
$$ language plpgsql;

-- Create trigger to enforce increment on updates
create trigger trigger_check_last_updated_block_increment
    before update on accounts
    for each row
    execute function check_last_updated_block_increment();

-- Also add a check constraint for basic non-negative validation
alter table accounts add constraint check_last_updated_block_positive 
    check (last_updated_block >= 0);


