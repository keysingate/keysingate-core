-- 001_bare_issuance.sql — учёт выдачи контейнеров bare.
--
-- Решение владельца 27.10: «номер N выдан хэшу X, больше ничего не фиксируется».
-- Поэтому в таблицах нет ни почты, ни имени, ни did, ни времени, ни статуса заявки.
--
-- Почему так:
--   * это книга выдачи, а не реестр людей: БД не должна позволять узнать, кому
--     выдан номер, — ни по запросу, ни при утечке, ни по решению суда;
--   * хэш необратим: holder_hmac = HMAC(секрет сервиса, email) для овнера,
--     domain_hmac = HMAC(секрет сервиса, did:web) для оркестратора; секрет живёт
--     в сервисе выдачи, не в БД, поэтому пересчитать хэш в БД невозможно;
--   * по хэшу сервис отвечает на единственный нужный вопрос — «этот держатель
--     уже получал бесплатный bare в этой выдаче?» — и ничего больше;
--   * нет времени и порядка — нет профилирования по датам и нет возможности
--     восстановить хронологию выдачи из этой таблицы;
--   * номер выдаётся один раз: (release_id, number) — первичный ключ, повторная
--     выдача того же номера в той же выдаче невозможна на уровне схемы.
--
-- Лимиты:
--   * releases.size — сколько номеров в выдаче (релиз 0: 100 000);
--   * unique (release_id, holder_hmac) — один бесплатный bare на держателя
--     в рамках выдачи;
--   * частичный unique (release_id, domain_hmac) where domain_hmac is not null —
--     один бесплатный bare на домен оркестратора в рамках выдачи.
--   * номер в диапазоне 1..size проверяется сервисом выдачи (схема знает только
--     number >= 1 и size > 0); в БД размер выдачи не Enforcement-ится триггером,
--     чтобы книга оставалась простой.
--
-- Доступ: RLS включён на обеих таблицах, политик нет — anon и authenticated не
-- видят ни строки. Публичной остаётся только страница «выдано N» через функцию
-- issued_count() (security definer, отдаёт лишь число).

begin;

-- releases: одна строка на выдачу (релиз). size — сколько номеров в ней.
create table releases (
    id   text primary key,
    size integer not null check (size > 0)
);

comment on table releases is
    'Выдачи номеров bare: id выдачи и её размер (релиз 0 — 100 000 номеров).';
comment on column releases.size is
    'Число номеров в выдаче; номера начинаются с 1.';

-- issuances: одна строка на выданный номер. Ничего, кроме номера и двух хэшей.
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
    'Книга выдачи: номер N выдан хэшу X. Почта, имя, did и время не хранятся.';
comment on column issuances.number is
    'Номер контейнера в выдаче, от 1 до releases.size.';
comment on column issuances.holder_hmac is
    'HMAC(секрет сервиса, email) для овнера или HMAC(секрет сервиса, did:web) для оркестратора; необратим.';
comment on column issuances.domain_hmac is
    'HMAC(секрет сервиса, did:web) домена оркестратора; null для овнера. Лимит на домен.';

-- Лимит на домен оркестратора: один бесплатный bare на домен в рамках выдачи.
create unique index issuances_domain_once_per_release
    on issuances (release_id, domain_hmac)
    where domain_hmac is not null;

-- RLS без политик: anon/authenticated не читают и не пишут ничего.
alter table releases enable row level security;
alter table issuances enable row level security;

-- issued_count(release_id) — число для открытой страницы «выдано N».
-- security definer: обходит RLS, но отдаёт только счётчик, ни одной строки.
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
    'Сколько номеров выдано в выдаче: для страницы «выдано N». Только число.';

revoke all on function issued_count(text) from public;

-- Роли anon/authenticated есть на Supabase, но не в чистом Postgres:
-- в песочнице гранты просто пропускаются.
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
