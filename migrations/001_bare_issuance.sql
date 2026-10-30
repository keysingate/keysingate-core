-- 001_bare_issuance.sql — accounting of bare container issuance.
--
-- Owner decision 27.10: "number N issued to hash X, nothing else is recorded".
-- Therefore the tables hold no email, no name, no did, no timestamp, no request status.
--
-- Why:
--   * this is an issuance ledger, not a people registry: the DB must not allow
--     finding out to whom a number was issued — neither by query, nor by leak,
--     nor by court order;
--   * hashes are irreversible: holder_hmac = HMAC(service secret, email) for the owner,
--     domain_hmac = HMAC(service secret, did:web) for the orchestrator; the secret lives
--     in the issuance service, not in the DB, so hashes cannot be recomputed inside the DB;
--   * by hash the service answers the only needed question — "has this holder
--     already received a free bare in this issuance?" — and nothing more;
--   * no timestamps and no order — no date-based profiling and no way to
--     reconstruct the issuance chronology from this table;
--   * a number is issued once: (release_id, number) is the primary key, re-issuance
--     of the same number within the same issuance is impossible at schema level.
--
-- Limits:
--   * releases.size — how many numbers are in the issuance (release 0: 100 000);
--   * unique (release_id, holder_hmac) — one free bare per holder
--     within an issuance;
--   * partial unique (release_id, domain_hmac) where domain_hmac is not null —
--     one free bare per orchestrator domain within an issuance.
--   * the number within 1..size is checked by the issuance service (the schema only knows
--     number >= 1 and size > 0); the issuance size is not enforced by a trigger in the DB,
--     to keep the ledger simple.
--
-- Access: RLS is enabled on both tables, no policies — anon and authenticated see
-- not a single row. The only public thing left is the "issued N" page via the
-- issued_count() function (security definer, returns only a count).

begin;

-- releases: one row per issuance (release). size — how many numbers it holds.
create table releases (
    id   text primary key,
    size integer not null check (size > 0)
);

comment on table releases is
    'Bare number issuances: issuance id and its size (release 0 — 100 000 numbers).';
comment on column releases.size is
    'Number of numbers in the issuance; numbers start at 1.';

-- issuances: one row per issued number. Nothing but the number and two hashes.
create table issuances (
    release_id  text not null references releases (id),
    number      integer not null,
    holder_hmac bytea not null,
    domain_hmac bytea null,
    primary key (release_id, number),
    constraint issuances_number_at_least_1 check (number >= 1),
    constraint issuances_holder_once_per_release unique (release_id, holder_hmac)
);

comment on table issuances is
    'Issuance ledger: number N issued to hash X. Email, name, did and time are not stored.';
comment on column issuances.number is
    'Container number within the issuance, from 1 to releases.size.';
comment on column issuances.holder_hmac is
    'HMAC(service secret, email) for the owner or HMAC(service secret, did:web) for the orchestrator; irreversible.';
comment on column issuances.domain_hmac is
    'HMAC(service secret, did:web) of the orchestrator domain; null for the owner. Per-domain limit.';

-- Orchestrator domain limit: one free bare per domain within an issuance.
create unique index issuances_domain_once_per_release
    on issuances (release_id, domain_hmac)
    where domain_hmac is not null;

-- RLS with no policies: anon/authenticated can neither read nor write anything.
alter table releases enable row level security;
alter table issuances enable row level security;

-- issued_count(release_id) — the count for the public "issued N" page.
-- security definer: bypasses RLS but returns only the counter, not a single row.
create function issued_count(p_release_id text)
    returns bigint
    language sql
    stable
    security definer
    set search_path = public, pg_temp
as $$
    select count(*)::bigint from issuances where release_id = p_release_id;
$$;

comment on function issued_count(text) is
    'How many numbers are issued within the issuance: for the "issued N" page. Count only.';

revoke all on function issued_count(text) from public;

-- The anon/authenticated roles exist on Supabase but not in plain Postgres:
-- in the sandbox the grants are simply skipped.
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        execute 'grant execute on function issued_count(text) to anon';
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        execute 'grant execute on function issued_count(text) to authenticated';
    end if;
end
$$;

commit;
