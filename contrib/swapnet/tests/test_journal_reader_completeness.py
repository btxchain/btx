"""Correctness readers must not mistake a bounded display page for the journal.

Real SQLite/Journal and production reader methods; session bodies, scheduler
callbacks and configuration drivers are synthetic. No chains, signing or wallet
operations are exercised. The bulk-row helper follows the existing capacity
fixture without importing its chain fixtures.
"""
from contextlib import contextmanager
import os
from types import SimpleNamespace

import pytest

from swapnet.application import Application
from swapnet.authorization import Authority, Principal
from swapnet.coordinator import Coordinator
from swapnet.errors import SwapError
from swapnet.journal import Journal, local_dump
from swapnet.policy import SafetyPolicy
from swapnet.store import Store


NOW = 1900000000
HIGH = 'f' * 64
ASSET = 'btc:' + 'b' * 64 + ':0:native'
OTHER_ASSET = 'btc:' + 'c' * 64 + ':0:native'
OWNER = Principal('p', True)
READER = Principal('p')


@contextmanager
def _book(path):
    os.chmod(path.parent, 0o700)
    store = Store(path)
    try:
        yield Journal(store)
    finally:
        store.close()


def _add_history(book, stage, count, start=1000):
    # Adapted from test_funding_scan_and_capacity.add_sessions. These rows are
    # retained unsigned history; readers must neither delete nor count them as
    # live settlements. Use a transaction to keep the fixture inexpensive.
    with book.store.transaction() as db:
        for n in range(start, start + count):
            sid = f'{n:064x}'
            body = {'stage': stage, 'principal': 'p', 'peer': 'q'}
            db.execute('INSERT INTO sn_negotiations VALUES(?,?,?,?,?,?)',
                       (sid, 0, 'p', 'q', stage, local_dump(body)))


def _session(book, sid, stage='offered', principal='p', asset=None):
    body = {'principal': principal, 'peer': 'q', 'stage': stage}
    if asset is not None:
        body['agreement'] = {'long_leg': {'asset': asset},
                             'short_leg': {'asset': 'btx:' + 'a' * 64 + ':0:native'}}
    book.save(sid, body)
    return body


def _scheduler(book, clock):
    seen = []
    coordinator = Coordinator(book, None, {}, None, None, None,
                              clock=lambda: clock[0],
                              policy=SafetyPolicy(terminal_recheck_seconds=60))
    coordinator.tick_one = seen.append
    return coordinator, seen


def _configuration_app(book):
    calls = []

    class Driver:
        def ready(self):
            calls.append('ready')
            return True

    original = Driver()

    def configure(policy):
        calls.append(('factory', dict(policy)))
        return Driver()

    app = SimpleNamespace(store=book.store, journal=book,
                          authority=Authority(book.store, book),
                          drivers={ASSET: original}, configure_asset=configure,
                          clear_startup_error=None)
    return app, calls, original


def _configure(app, ctx, asset):
    return Application.rpc_setswapassetpolicy(app, ctx, {'asset': asset})


def _events(app, ctx, after, limit=100):
    return Application.rpc_getswapevents(app, ctx, after, limit)


def _cursor(book):
    return book.store.db.execute('SELECT COALESCE(MAX(seq),0) FROM audit').fetchone()[0]


def _labels(result):
    return [event['event']['label'] for event in result['events']]


def test_scheduler_reaches_live_session_after_retained_history_and_reopen(tmp_path):
    path = tmp_path / 'state.sqlite'
    with _book(path) as book:
        _session(book, HIGH)
        coordinator, seen = _scheduler(book, [NOW])
        for _ in range(12):
            coordinator.tick()
        assert seen == [HIGH] * 12
        _add_history(book, 'cancelled', 4096)
        _add_history(book, 'rejected', 4096, start=10000)
        book.ensure_capacity()
        assert len(book.all()) == 512
        assert len(book.all(limit=4096)) == 4096
        assert HIGH not in {sid for sid, _, _ in book.all(limit=4096)}
        seen.clear()
        for _ in range(12):
            coordinator.tick()
        assert seen == [HIGH] * 12
        assert book.load(HIGH)[1]['stage'] == 'offered'
        assert book.store.db.execute('SELECT count(*) FROM sn_negotiations').fetchone()[0] == 8193
        assert book.store.verify_audit()
    with _book(path) as book:
        coordinator, seen = _scheduler(book, [NOW])
        for _ in range(12):
            coordinator.tick()
        assert seen == [HIGH] * 12
        assert book.store.db.execute('SELECT count(*) FROM sn_negotiations').fetchone()[0] == 8193


def test_scheduler_rotates_seven_active_sessions_four_per_pass(store):
    book = Journal(store)
    ids = [f'{n:064x}' for n in range(1, 8)]
    for sid in ids:
        _session(book, sid)
    coordinator, seen = _scheduler(book, [NOW])
    coordinator.tick()
    first = seen[:]
    assert len(first) == 4 and len(set(first)) == 4
    seen.clear()
    coordinator.tick()
    assert len(seen) == 4 and len(set(seen)) == 4
    assert set(first + seen) == set(ids)
    assert first != seen


def test_terminal_watch_survives_history_and_keeps_cadence_and_wrap(store):
    book = Journal(store)
    active_ids = [f'{n:064x}' for n in range(1, 8)]
    for sid in active_ids:
        _session(book, sid)
    complete, refunded = 'e' * 64, HIGH
    _session(book, complete, 'complete')
    _session(book, refunded, 'refunded')
    _add_history(book, 'cancelled', 4096)
    _add_history(book, 'rejected', 4096, start=10000)
    clock = [NOW]
    coordinator, seen = _scheduler(book, clock)

    def tick_at(timestamp):
        clock[0] = timestamp
        seen.clear()
        coordinator.tick()
        active = [sid for sid in seen if sid in active_ids]
        terminal = [sid for sid in seen if sid in {complete, refunded}]
        assert len(active) == 4 and len(set(active)) == 4
        assert len(seen) == len(active) + len(terminal)
        return terminal

    assert tick_at(NOW) == [complete]
    assert tick_at(NOW) == []
    assert tick_at(NOW + 59) == []
    assert tick_at(NOW + 60) == [refunded]
    assert tick_at(NOW + 119) == []
    assert tick_at(NOW + 120) == [complete]
    assert store.db.execute('SELECT count(*) FROM sn_negotiations').fetchone()[0] == 8201


@pytest.mark.parametrize('history_count', [0, 512])
def test_asset_guard_is_complete_before_configuration_side_effects(store, history_count):
    book = Journal(store)
    active = _session(book, HIGH, 'funded', asset=ASSET)
    _add_history(book, 'cancelled', history_count)
    app, calls, original = _configuration_app(book)
    with pytest.raises(SwapError) as error:
        _configure(app, READER, ASSET)
    assert error.value.code == 'OWNER_REQUIRED'
    assert calls == []
    assert _configure(app, OWNER, OTHER_ASSET) == {'asset': OTHER_ASSET, 'ready': True}
    assert calls == [('factory', {'asset': OTHER_ASSET}), 'ready']
    calls.clear()
    policy_before = book.setting('asset_policies')
    with pytest.raises(SwapError) as error:
        _configure(app, OWNER, ASSET)
    assert error.value.code == 'ASSET_BUSY'
    assert calls == []
    assert app.drivers[ASSET] is original
    assert book.setting('asset_policies') == policy_before
    assert book.load(HIGH)[1] == active


def test_guard_does_not_assume_active_updates_remain_below_admission_cap(store):
    book = Journal(store)
    ids = [f'{n:064x}' for n in range(1, 131)]
    # Admit terminal history normally, then model stage changes of already
    # retained sessions (for example reorg reconciliation). No new row evades
    # admission; production save intentionally does not re-admit old rows.
    for sid in ids:
        _session(book, sid, 'complete', asset=OTHER_ASSET)
    for sid in ids:
        revision, body = book.load(sid)
        body['stage'] = 'reconciling'
        if sid == ids[-1]:
            body['agreement']['long_leg']['asset'] = ASSET
        book.save(sid, body, revision)
    assert store.db.execute("SELECT count(*) FROM sn_negotiations WHERE stage='reconciling'").fetchone()[0] == 130
    with pytest.raises(SwapError) as error:
        book.ensure_capacity()
    assert error.value.code == 'ACTIVE_LIMIT'
    app, calls, original = _configuration_app(book)
    with pytest.raises(SwapError) as error:
        _configure(app, OWNER, ASSET)
    assert error.value.code == 'ASSET_BUSY'
    assert calls == [] and app.drivers[ASSET] is original
    assert book.setting('asset_policies') is None


@pytest.mark.parametrize('stage', ['complete', 'refunded', 'cancelled', 'rejected'])
def test_closed_history_does_not_block_asset_configuration(store, stage):
    book = Journal(store)
    _session(book, HIGH, stage, asset=ASSET)
    app, calls, original = _configuration_app(book)
    assert _configure(app, OWNER, ASSET) == {'asset': ASSET, 'ready': True}
    assert calls == [('factory', {'asset': ASSET}), 'ready']
    assert app.drivers[ASSET] is not original
    assert book.setting('asset_policies') == {ASSET: {'asset': ASSET}}


def test_event_ownership_outside_display_page_preserves_privacy_and_cursor(store):
    book = Journal(store)
    _session(book, HIGH)
    app = SimpleNamespace(store=store, journal=book)
    before = _cursor(book)
    store.audit({'type': 'reader_control', 'swap_id': HIGH, 'label': 'baseline'})
    assert _labels(_events(app, READER, before)) == ['baseline']
    _add_history(book, 'cancelled', 512)
    other = 'e' * 64
    _session(book, other, principal='other')
    assert HIGH not in {sid for sid, _, _ in book.all(READER.name)}
    before = _cursor(book)
    inside = f'{1000:064x}'
    payloads = [
        {'swap_id': inside, 'label': 'own_inside'},
        {'swap_id': HIGH, 'label': 'own_outside_swap_id'},
        {'id': HIGH, 'label': 'own_outside_id'},
        {'swap_id': other, 'label': 'other'},
        {'id': 'unassociated', 'label': 'unassociated'},
        {'id': HIGH, 'swap_id': other, 'label': 'swap_id_precedence'},
        {'id': HIGH, 'swap_id': None, 'label': 'null_does_not_fall_back'},
    ]
    for payload in payloads:
        store.audit({'type': 'reader_control', **payload})
    owner = _events(app, OWNER, before)
    reader = _events(app, READER, before)
    stranger = _events(app, Principal('other'), before)
    assert _labels(owner) == [payload['label'] for payload in payloads]
    assert _labels(reader) == ['own_inside', 'own_outside_swap_id', 'own_outside_id']
    assert _labels(stranger) == ['other', 'swap_id_precedence']
    assert reader['next_sequence'] == owner['next_sequence'] == _cursor(book)
    assert _events(app, READER, reader['next_sequence']) == {
        'events': [], 'next_sequence': reader['next_sequence']}
    # Page the same mixed raw stream one row at a time: a private row can yield
    # no visible events but must still advance, without skipping later own rows.
    cursor, visible = before, []
    for payload in payloads:
        page = _events(app, READER, cursor, 1)
        assert page['next_sequence'] == cursor + 1
        visible.extend(_labels(page))
        cursor = page['next_sequence']
    assert visible == _labels(reader)
    assert cursor == owner['next_sequence']
    assert store.verify_audit()


def test_event_ownership_lookup_accepts_full_500_id_audit_page(store):
    book = Journal(store)
    _add_history(book, 'cancelled', 512)
    ids = [f'{n:064x}' for n in range(10000, 10500)]
    # Synthetic retained rows are sufficient: event authorization reads ownership,
    # not execution state. All500 owned references sort beyond the old prefix.
    _add_history(book, 'refunded', 500, start=10000)
    before = _cursor(book)
    for sid in ids:
        store.audit({'type': 'reader_control', 'swap_id': sid, 'label': sid})
    app = SimpleNamespace(store=store, journal=book)
    result = _events(app, READER, before, 500)
    assert _labels(result) == ids
    assert len(result['events']) == 500
    assert result['next_sequence'] == before + 500
    assert _events(app, Principal('other'), before, 500)['events'] == []


def test_legacy_overcap_terminal_history_does_not_truncate_rotation(store):
    book = Journal(store)
    _session(book, HIGH)
    # An existing over-cap database must remain observable even though new
    # session admission is refused. No limit increase or history deletion.
    _add_history(book, 'complete', 4097, start=1000)
    with pytest.raises(SwapError, match='SESSION_LIMIT'):
        book.ensure_capacity()
    clock = [NOW]
    coordinator, seen = _scheduler(book, clock)
    watched = []
    for _ in range(4097):
        seen.clear()
        coordinator.tick()
        assert HIGH in seen and len(seen) == 2
        watched.extend(sid for sid in seen if sid != HIGH)
        clock[0] += 60
    assert len(set(watched)) == 4097
    assert store.db.execute('SELECT count(*) FROM sn_negotiations').fetchone()[0] == 4098


def test_scheduler_reaches_sessions_after_active_terminal_stage_changes(store):
    book = Journal(store)
    ids = [f'{n:064x}' for n in range(1, 7)]
    for sid in ids:
        _session(book, sid)
    terminal = 'e' * 64
    _session(book, terminal, 'complete')
    clock = [NOW]
    coordinator, seen = _scheduler(book, clock)
    coordinator.tick()
    for sid, stage in [(ids[0], 'complete'), (terminal, 'reconciling')]:
        revision, body = book.load(sid)
        body['stage'] = stage
        book.save(sid, body, revision)
    seen.clear()
    for _ in range(4):
        clock[0] += 60
        coordinator.tick()
    assert set(seen) == set(ids + [terminal])
    assert book.load(terminal)[1]['stage'] == 'reconciling'
