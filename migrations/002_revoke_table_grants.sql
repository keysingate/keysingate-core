-- 002_revoke_table_grants.sql — второй замок поверх RLS.
--
-- Зачем:
--   * на Supabase роли anon и authenticated по умолчанию получают права на новые
--     таблицы в schema public через default privileges (alter default privileges
--     ... grant all on tables): таблица появляется с уже выданным ALL, и барьер
--     остаётся единственным — RLS без политик;
--   * одного барьера мало: ошибка в политике, отключение RLS или забытый
--     security definer открывают таблицу целиком. Поэтому права отзываются
--     явно, на уровне грантов, — вторым замком;
--   * отзываем all (select, insert, update, delete, truncate, references,
--     trigger): этим таблицам публичный доступ не нужен ни в каком виде;
--   * execute на issued_count(text) у anon/authenticated остаётся — через него
--     публично доступно только число выданных номеров, ни одной строки.
--
-- Роли anon/authenticated есть на Supabase, но не в чистом Postgres: в песочнице
-- гранты просто пропускаются (как в 001).

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
    'HMAC(секрет сервиса, домен оркестратора) — сам домен, без пути did:web; null для овнера. Лимит на домен.';

commit;
