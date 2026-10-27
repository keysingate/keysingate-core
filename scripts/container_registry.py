#!/usr/bin/env python3
"""Реестр функций ПО внутри контейнера и того, какими тестами они пройдены.

Внутри контейнера — два крейта: `ksg-container` (кнопки, цикл, слои, ключ
клиента) и `ksg-journal` (журнал работы). Для каждой их функции реестр
записывает, выполнялась ли она тестами и какими:

  * модульные и интеграционные тесты — всё, кроме стенда;
  * e2e — сценарии стенда (`tests/e2e_stand.rs`): вся жизнь контейнера через кнопки;
  * смоук — `tests/smoke_stand.rs`.

«Выполнялась» — факт из покрытия (`cargo llvm-cov`), а не из статического
графа: в Rust граф вызовов не разрешает вызовы методов через получатель, и
GitNexus видит из тестов лишь часть функций. GitNexus используется для описи:
реестр сверяет список функций покрытия со списком символов индекса и называет
расхождения.

Результат: `[doc:CONTAINER-FUNCTIONS]` (генерируется, руками не править) и
`[doc:CONTAINER-FUNCTIONS-JSON]`; каталог вывода задаёт `KSG_DOCS_DIR`.

Требуется: `cargo-llvm-cov`, компонент `llvm-tools-preview`, `rustfilt`.
Запуск из корня этого каталога (core v2): `python3 scripts/container_registry.py`.
Код выхода 1 — если тест упал или какая-то операция кнопок не прошла на стенде.
"""

import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT
# С 01.10 ядро v2: журнал переехал в ядро (`ksg-core-v2`).
CRATES = ('ksg-container-v2', 'ksg-core-v2')
# Реестр — приватный документ, он лежит вне этого каталога: `[doc:CONTAINER-FUNCTIONS]`
# и `[doc:CONTAINER-FUNCTIONS-JSON]`. Каталог вывода — KSG_DOCS_DIR.
REPO = ROOT.parent
DOCS = Path(os.environ.get('KSG_DOCS_DIR', REPO / 'internal'))
OUT_MD = DOCS / 'Reestr_funktsiy_konteynera.md'
OUT_JSON = DOCS / 'reestr_funktsiy_konteynera.json'

# Модули, через которые идёт нажатие кнопки: цикл §3.3 и всё, что он зовёт
# на шагах 1–9. Функции этих модулей помечаются в реестре отдельно.
BUTTON_PATH = {
    'ksg-container/src/command.rs', 'ksg-container/src/event.rs',
    'ksg-container/src/operation.rs', 'ksg-container/src/container.rs',
    'ksg-container/src/unload_gate.rs', 'ksg-container/src/client_key.rs',
    'ksg-container/src/timecheck.rs', 'ksg-container/src/followup.rs',
    'ksg-container/src/order.rs', 'ksg-container/src/artifact.rs',
    'ksg-container/src/dispute.rs', 'ksg-container/src/seal.rs',
}

# Ветки, которые тестом не вызвать, с причиной. Не пропуск, а граница: реестр
# выводит их отдельно. Ключ — (файл, имя функции по покрытию).
UNREACHABLE = {
    # --- core v2 (since 01.10): ksg-container-v2 -----------------------------
    ('ksg-container-v2/src/noise.rs', 'ksg_container_v2::noise::pad::{closure#0}'):
        'длина содержимого больше u32::MAX (4 ГиБ) — размер раскладки задаётся при печати и меньше',
    ('ksg-container-v2/src/client_key.rs', 'answer::{closure#0}'):
        'FROST dkg::part2 отдаёт пакет второго раунда на каждый пакет первого; '
        'пакет первого раунда один — мобильной стороны, и пакет для неё всегда есть',
    ('ksg-container-v2/src/client_key.rs', 'finish::{closure#1}'):
        '`begin` ставит коммитмент клиента к единственному подписанту группы, если второго нет, '
        'и FROST round2::sign отказывает раньше: коммитмент не свой. Тест '
        '`registry_gaps.rs::a_stored_half_rewritten_to_sign_alone_signs_nothing`',
    ('ksg-container-v2/src/client_key.rs', 'client_public::{closure#0}'):
        'ключ Ed25519 FROST сериализуется ровно в 32 байта',
    ('ksg-container-v2/src/client_key.rs', 'share_public::{closure#0}'):
        'доля проверки Ed25519 FROST сериализуется ровно в 32 байта',
    ('ksg-container-v2/src/client_key.rs', 'sign_alone::{closure#0}'):
        'секретная доля FROST сериализуется ровно в 32 байта',
    ('ksg-container-v2/src/client_key.rs', 'sign_alone::{closure#1}'):
        'секретная доля — канонический скаляр: FROST не читает неканонический при десериализации',
    ('ksg-container-v2/src/client_key.rs', 'from_bytes::{closure#1}'):
        'срез из get(..4) в [u8; 4] — длина уже 4, преобразование не падает',
    ('ksg-container-v2/src/client_key.rs', 'from_bytes::{closure#2}'):
        'u32 в usize — не падает на платформах от 32 бит, а других у эталона нет',
    ('ksg-container-v2/src/container.rs', 'to_state::{closure#0}'):
        'сериализация элемента FROST падает только на нейтральной точке группы; FROST её не '
        'десериализует, а у ключа от генератора вероятность ≈2^-252',
    ('ksg-container-v2/src/container.rs', 'to_state::{closure#1}'):
        'то же для половины прежнего клиента: нейтральная точка не читается и не рождается',
    ('ksg-container-v2/src/store.rs', 'seal_to_bytes::{closure#0}'):
        'serde_json::to_vec состояния со строковыми ключами не падает',
    ('ksg-container-v2/src/store.rs', 'stored_len::{closure#0}'):
        'serde_json::to_vec состояния со строковыми ключами не падает',
    ('ksg-container-v2/src/store.rs', 'stored_packed_len::{closure#0}'):
        'serde_json::to_vec состояния со строковыми ключами не падает',
    ('ksg-container-v2/src/store.rs', 'seal_to_bytes::{closure#2}'):
        'serde_json::to_vec подписи (три строковых поля) не падает',
    ('ksg-container-v2/src/store.rs', 'seal_to_bytes::{closure#3}'):
        'подпись ML-DSA-65 в JSON — около 4,5 КиБ, меньше u32::MAX',
    # --- core v2: ksg-core-v2 -------------------------------------------------
    ('ksg-core-v2/src/crypto/sign.rs', 'ksg_core_v2::crypto::sign::verify_one::{closure#7}'):
        'любые 1952 байта читаются как ключ ML-DSA-65: коэффициенты t1 по 10 бит, '
        'все значения в диапазоне (fips204 pk_decode)',
    ('ksg-core-v2/src/doc/mod.rs', 'from_unix_ms::{closure#0}'):
        'u64::MAX / 86_400_000 меньше i64::MAX',
    ('ksg-core-v2/src/doc/mod.rs', 'millis_of::{closure#3}'):
        'год не раньше 1970 проверен выше, число дней от эпохи не отрицательно',
    ('ksg-core-v2/src/journal/mod.rs', 'draft::{closure#0}'):
        'больше 2^32 страниц в одной записи: `place` отказывает за ёмкостью зон (1102 страницы)',
    ('ksg-core-v2/src/journal/mod.rs', 'draft::{closure#1}'):
        'больше 2^32 страниц в одной записи — больше 128 ГиБ тел в памяти; зоны держат 1102',
    ('ksg-core-v2/src/journal/mod.rs', 'draft_record::{closure#1}'):
        'больше 2^32 частей в записи: `draft_pages_only` раньше упирается в ёмкость зон',
    ('ksg-core-v2/src/journal/mod.rs', 'draft_pages_only::{closure#0}'):
        'больше 2^32 страниц в одной записи: `place` отказывает за ёмкостью зон (1102 страницы)',
    ('ksg-core-v2/src/journal/mod.rs', 'draft_pages_only::{closure#1}'):
        'больше 2^32 частей в одной записи — больше 128 ГиБ частей в памяти',
    ('ksg-core-v2/src/journal/mod.rs', 'export_one::{closure#0}'):
        'u64 в usize падает только на 32-битной цели за 2^32, а журнала с такой страницей там нет',
    ('ksg-core-v2/src/journal/mod.rs', 'export_one::{closure#1}'):
        'страница найдена среди страниц журнала, а у цепочки лист на каждую страницу: '
        'доказательство включения строится',
    ('ksg-core-v2/src/journal/mod.rs', 'export_pages::{closure#0}'):
        'u64 в usize падает только на 32-битной цели за 2^32, а журнала с такой страницей там нет',
    ('ksg-core-v2/src/journal/mod.rs', 'export_pages::{closure#1}'):
        'страница найдена среди страниц журнала, а у цепочки лист на каждую страницу',
    ('ksg-core-v2/src/journal/mod.rs', 'expert_pages::{closure#0}::{closure#0}'):
        'u64 в usize падает только на 32-битной цели за 2^32, а журнала с такой страницей там нет',
    ('ksg-core-v2/src/journal/mod.rs', 'expert_pages::{closure#0}::{closure#1}'):
        'страница найдена среди страниц журнала, а у цепочки лист на каждую страницу',
    ('ksg-core-v2/src/merkle/inclusion.rs',
     'ksg_core_v2::merkle::inclusion::inclusion_proof::{closure#0}'):
        'u64 в usize падает только на 32-битной цели за 2^32 листьев, которых там не уместить',
}


def run(cmd, env=None, check=False):
    r = subprocess.run(cmd, cwd=IMPL, capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        sys.stderr.write(r.stdout[-4000:] + r.stderr[-4000:])
        sys.exit(f'команда упала: {" ".join(cmd)}')
    return r


def coverage(label, test_args, extra_env=None):
    """Один прогон тестов под покрытием. Возвращает (сводку тестов, функции)."""
    pkgs = [a for c in CRATES for a in ('-p', c)]
    env = dict(os.environ, **(extra_env or {}))
    run(['cargo', 'llvm-cov', 'clean', '--workspace'])
    r = run(['cargo', 'llvm-cov', '--no-report', *pkgs, *test_args], env=env)
    passed = sum(int(m) for m in re.findall(r'test result: \w+\. (\d+) passed', r.stdout))
    failed = sum(int(m) for m in re.findall(r'(\d+) failed', r.stdout))
    ok = r.returncode == 0
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        path = f.name
    run(['cargo', 'llvm-cov', 'report', '--json', *pkgs, '--output-path', path], check=True)
    data = json.load(open(path))['data'][0]['functions']
    os.unlink(path)
    return {'label': label, 'ok': ok, 'passed': passed, 'failed': failed}, data


def demangle(names):
    try:
        r = subprocess.run(['rustfilt'], input='\n'.join(names), capture_output=True, text=True)
        out = r.stdout.splitlines()
        if len(out) == len(names):
            return out
    except FileNotFoundError:
        pass
    return names


def normalize(name):
    """Имя функции без хеша и параметров обобщения — одно на все инстанциации."""
    name = name.split('::h')[0] if re.search(r'::h[0-9a-f]{16}$', name) else name
    prev = None
    while prev != name:
        prev = name
        name = re.sub(r'<[^<>]*>', '', name)
    return name.replace('::::', '::').strip(':')


def functions(raw):
    """{(файл, имя): (строка, счётчик)} только для функций внутри контейнера."""
    picked = [f for f in raw if any(f'{c}/src/' in f['filenames'][0] for c in CRATES)]
    names = demangle([f['name'] for f in picked])
    out = {}
    for f, n in zip(picked, names):
        rel = f['filenames'][0].split('crates/', 1)[1]
        key = (rel, normalize(n))
        line = f['regions'][0][0] if f['regions'] else 0
        prev = out.get(key)
        count = f['count'] + (prev[1] if prev else 0)
        out[key] = (min(line, prev[0]) if prev else line, count)
    return out


def gitnexus_inventory():
    """Функции в индексе GitNexus по крейтам контейнера, если индекс есть."""
    runner = REPO / '.gitnexus' / 'run.cjs'
    if not runner.exists():
        return None
    q = ("MATCH (f:Function) WHERE f.filePath CONTAINS 'ksg-container/src' "
         "OR f.filePath CONTAINS 'ksg-journal/src' RETURN f.name, f.filePath, f.startLine")
    r = subprocess.run(['node', str(runner), 'cypher', q, '--repo', '.'],
                       cwd=REPO, capture_output=True, text=True)
    try:
        md = json.loads(r.stdout[r.stdout.index('{'):])['markdown']
    except (ValueError, KeyError):
        return None
    rows = [l.split('|')[1:-1] for l in md.splitlines()[2:]]
    return {(c[1].strip().split('crates/', 1)[-1], c[0].strip()) for c in rows if len(c) >= 2}


def operations():
    """Операции кнопок: имя → кнопка, из таблицы `Operation::button`."""
    src = (IMPL / 'crates/ksg-container-v2/src/operation.rs').read_text()
    body = src[src.index('pub const fn button'):]
    body = body[:body.index('\n    }\n')]
    out = {}
    for m in re.finditer(r'((?:\s*\|?\s*Self::\w+)+)\s*=>\s*Button::(\w+)', body):
        for op in re.findall(r'Self::(\w+)', m.group(1)):
            out[op] = m.group(2)
    return out


def main():
    date = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    sha = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], cwd=ROOT,
                         capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(['git', 'status', '--porcelain', '--', '.'], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    version = sha + (' + незакоммиченные правки' if dirty else '')

    report = Path(tempfile.gettempdir()) / 'ksg_stand_pressed.txt'
    if report.exists():
        report.unlink()
    unit_run, unit_raw = coverage('модульные и интеграционные', ['--', '--skip', 'e2e_', '--skip', 'smoke_'])
    e2e_run, e2e_raw = coverage('e2e (стенд)', ['--test', 'e2e_stand'],
                                {'KSG_STAND_REPORT': str(report)})
    smoke_run, smoke_raw = coverage('смоук (стенд)', ['--test', 'smoke_stand'])
    all_run, all_raw = coverage('все', [])

    unit, e2e, smoke, every = (functions(x) for x in (unit_raw, e2e_raw, smoke_raw, all_raw))
    pressed = set(re.findall(r'"(\w+)"', report.read_text())) if report.exists() else set()
    ops = operations()

    rows = []
    for (rel, name), (line, count) in sorted(every.items(), key=lambda kv: (kv[0][0], kv[1][0])):
        rows.append({
            'function': name, 'file': rel, 'line': line,
            'button_path': rel in BUTTON_PATH,
            'unit': unit.get((rel, name), (0, 0))[1],
            'e2e': e2e.get((rel, name), (0, 0))[1],
            'smoke': smoke.get((rel, name), (0, 0))[1],
        })
    zero = [r for r in rows if r['unit'] == 0 and r['e2e'] == 0 and r['smoke'] == 0]
    never = [r for r in zero if (r['file'], r['function']) not in UNREACHABLE]
    bounded = [r for r in zero if (r['file'], r['function']) in UNREACHABLE]

    gn = gitnexus_inventory()
    gn_note = ''
    if gn is not None:
        cov_short = {(r['file'], r['function'].split('::')[-1]) for r in rows}
        only_gn = sorted(k for k in gn if k not in cov_short)
        gn_note = (f'GitNexus: {len(gn)} символов-функций в тех же файлах; '
                   f'нет в покрытии: {len(only_gn)} (обычно `const fn`, подставленные '
                   f'компилятором, и функции тестовых модулей `#[cfg(test)]`).')

    ops_rows = [{'operation': op, 'button': b, 'e2e': op in pressed or op == 'PrintRelease'}
                for op, b in ops.items()]
    ops_missing = [o['operation'] for o in ops_rows if not o['e2e']]

    runs = [unit_run, e2e_run, smoke_run, all_run]
    doc = {'date': date, 'version': version, 'runs': runs, 'operations': ops_rows,
           'functions': rows,
           'never_executed': [f"{r['file']}:{r['line']} {r['function']}" for r in never],
           'unreachable': [f"{r['file']}:{r['line']} {r['function']}" for r in bounded]}
    OUT_JSON.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + '\n')

    L = []
    L.append('# Реестр функций ПО внутри контейнера\n')
    L.append('**Генерируется** `scripts/container_registry.py`. Руками не править.\n')
    L.append(f'**Прогон:** {date} · **версия:** `{version}`\n')
    L.append('«Выполнялась» — факт из покрытия (`cargo llvm-cov`): функция исполнялась '
             'хотя бы раз в прогоне этого набора тестов. Число — счётчик исполнений.\n')
    L.append('## 1. Прогоны\n')
    L.append('| Набор | Итог | Пройдено | Упало |')
    L.append('|---|---|---|---|')
    for r in runs:
        L.append(f"| {r['label']} | {'зелёный' if r['ok'] else '**красный**'} | {r['passed']} | {r['failed']} |")
    L.append('')
    L.append('## 2. Операции кнопок на стенде (e2e)\n')
    L.append('`PrintRelease` — запись 0 секции статуса, ложится при сборке, до кнопок.\n')
    L.append('| Операция | Кнопка | Прошла через кнопку на стенде |')
    L.append('|---|---|---|')
    names = {'Issuer': 'D-1 эмитента', 'Signatures': 'D-2 подписей', 'Export': 'D-3 выгрузки'}
    for o in ops_rows:
        L.append(f"| `{o['operation']}` | {names.get(o['button'], o['button'])} | {'да' if o['e2e'] else '**нет**'} |")
    L.append('')
    L.append(f'## 3. Функции — {len(rows)}; пропусков — {len(never)}, '
             f'невызываемых по устройству — {len(bounded)}\n')
    if gn_note:
        L.append(gn_note + '\n')
    L.append('«Кнопки» — функция в модуле, через который идёт нажатие (цикл §3.3).\n')
    L.append('| № | Функция | Файл:строка | Кнопки | Модульные | e2e | Смоук |')
    L.append('|---|---|---|---|---|---|---|')
    for i, r in enumerate(rows, 1):
        mark = lambda n: str(n) if n else '**0**'
        L.append(f"| {i} | `{r['function']}` | `{r['file']}:{r['line']}` | "
                 f"{'да' if r['button_path'] else ''} | {mark(r['unit'])} | {r['e2e'] or 0} | {r['smoke'] or 0} |")
    L.append('')
    L.append('## 4. Ни разу не выполнялись — пропуски\n')
    if never:
        for r in never:
            L.append(f"- `{r['file']}:{r['line']}` `{r['function']}`")
    else:
        L.append('Нет.')
    L.append('')
    if bounded:
        L.append('## 5. Не вызываются тестом по устройству — границы\n')
        for r in bounded:
            L.append(f"- `{r['file']}:{r['line']}` `{r['function']}` — "
                     f"{UNREACHABLE[(r['file'], r['function'])]}")
        L.append('')
    L.append('## 6. Порядок работы воркера\n')
    L.append('1. `python scripts/container_registry.py` — прогоны и этот файл.')
    L.append('2. Раздел 4 не пуст — на каждую функцию тест, названный по тому, что он '
             'удерживает; сценарный — на стенде (`tests/stand/`), точечный — в '
             '`tests/registry_gaps.rs`.')
    L.append('3. Раздел 2 содержит «нет» — сценарий стенда, доводящий операцию до кнопки.')
    L.append('4. Функцию нельзя вызвать тестом — причина в `UNREACHABLE` скрипта, не молчание.')
    L.append('5. Повторить п. 1, закоммитить реестр вместе с тестами.')
    L.append('')
    OUT_MD.write_text('\n'.join(L))

    print(f'{OUT_MD.relative_to(ROOT)}: функций {len(rows)}, не выполнялись {len(never)}, '
          f'операций без e2e {len(ops_missing)}')
    for r in runs:
        print(f"  {r['label']}: {'ok' if r['ok'] else 'FAILED'} {r['passed']} пройдено, {r['failed']} упало")
    if not all(r['ok'] for r in runs) or ops_missing or never:
        if never:
            print('  пропуски:', ', '.join(f"{r['file']}:{r['line']}" for r in never), file=sys.stderr)
        if ops_missing:
            print('  операции без e2e:', ', '.join(ops_missing), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
