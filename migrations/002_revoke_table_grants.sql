-- 002_revoke_table_grants.sql — second lock on top of RLS.
--
-- Why:
--   * on Supabase the anon and authenticated roles get rights on new
--     tables in schema public by default via default privileges (alter default privileges
--     ... grant all on tables): a table appears with ALL already granted, and the barrier
--     remains the only one — RLS with no policies;
--   * one barrier is not enough: a policy mistake, disabled RLS, or a forgotten
--     security definer open the whole table. So rights are revoked
--     explicitly, at grant level — as a second lock;
--   * we revoke all (select, insert, update, delete, truncate, references,
--     trigger): these tables need no public access of any kind;
--   * execute on issued_count(text) stays for anon/authenticated — through it
--     only the count of issued numbers is publicly available, not a single row.
--
-- The anon/authenticated roles exist on Supabase but not in plain Postgres: in the sandbox
-- the grants are simply skipped (as in 001).

begin;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'anon') then
        execute 'revoke all on table releases, issuances from anon';
    end if;
    if exists (select 1 from pg_roles where rolname = 'authenticated') then
        execute 'revoke all on table releases, issuances from authenticated';
    end if;
end
$$;

comment on column issuances.domain_hmac is
    'HMAC(service secret, orchestrator domain) — the domain itself, without the did:web path; null for the owner. Per-domain limit.';

commit;
