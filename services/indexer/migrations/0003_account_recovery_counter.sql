alter table accounts
    add column if not exists recovery_counter bigint not null default 0;

comment on column accounts.recovery_counter is
    'number of `AccountRecovered` events observed.compared against the recovery counter in packed data to detect revoked authenticators.';
