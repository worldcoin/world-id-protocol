-- Rename table to accounts
alter table account_created_events rename to accounts;

-- Add authenticator_pubkeys column
alter table accounts add column authenticator_pubkeys jsonb not null default '[]';

-- Update the column to ensure it's always an array
alter table accounts alter column authenticator_pubkeys set default '[]';

