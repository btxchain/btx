"""Terminal polling must retain recovery without redundant durable snapshots."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from test_execution_v2 import pair, B
from swapnet.errors import SwapError


@pytest.fixture(params=['complete', 'refunded'])
def terminal_pair(pair, request):
    pair.start()
    if request.param == 'complete':
        for _ in range(18):
            pair.step()
    else:
        pair.deliver()
        coordinator = pair.nodes['alice'][3]
        coordinator.tick()
        coordinator.tick()
        pair.a.mine(3)
        pair.a.height = pair.state('alice')['agreement']['long_leg']['lock_value']
        pair.b.height += 1
        for _ in range(4):
            coordinator.tick()
            pair.a.mine()
            pair.time.n += 1
    assert pair.state('alice')['stage'] == request.param
    # Pair.step mines after the coordinator runs. Observe that final block.
    pair.nodes['alice'][3].tick()
    return pair


def saved_snapshot(pair):
    store, journal, _, _ = pair.nodes['alice']
    events = [json.loads(row[0]) for row in store.db.execute('SELECT body FROM audit')]
    return journal.load(pair.sid), len(events), sum(
        event.get('type') == 'swap_v2_saved' and event.get('id') == pair.sid
        for event in events
    )


def test_unchanged_terminal_ticks_do_not_write(terminal_pair):
    pair = terminal_pair
    initial = saved_snapshot(pair)
    for _ in range(10):
        pair.nodes['alice'][3].tick()
    assert saved_snapshot(pair) == initial
    # Even after the stored observation has aged, decide must use fresh drivers.
    pair.time.n += pair.nodes['alice'][3].policy.max_observation_age_seconds + 1
    for _ in range(10):
        pair.time.n += 1
        pair.nodes['alice'][3].tick()
    assert saved_snapshot(pair) == initial
    pair.restart('alice')
    for _ in range(10):
        pair.time.n += 1
        pair.nodes['alice'][3].tick()
    assert saved_snapshot(pair) == initial
    assert pair.nodes['alice'][0].verify_audit()


def test_changed_chain_evidence_recovers_after_reopen(terminal_pair):
    pair = terminal_pair
    store, journal, _, coordinator = pair.nodes['alice']
    initial, _, _ = saved_snapshot(pair)
    stage = initial[1]['stage']
    operations = journal.operations(pair.sid)
    reservation = store.db.execute(
        'SELECT state,cost FROM reservations WHERE id=?',
        (initial[1]['reservation_id'],)
    ).fetchone()
    pair.a.mine()
    pair.b.mine()
    pair.time.n += 1
    coordinator.tick()
    changed = saved_snapshot(pair)
    assert changed[0][0] > initial[0]
    assert changed[0][1]['observations']['a']['confirmations'] > initial[1]['observations']['a']['confirmations']
    pair.restart('alice')
    assert saved_snapshot(pair) == changed
    # Reopen before the reorg as well, so detection cannot rely on a live cache.
    ledger = pair.b if stage == 'complete' else pair.a
    ledger.rollback_spend()
    pair.time.n += 1
    pair.nodes['alice'][3].tick()
    recovered = saved_snapshot(pair)
    assert recovered[0][1]['stage'] == ('claim_broadcast' if stage == 'complete' else 'refund_broadcast')
    assert recovered[0][1]['last_action'] == ('rebroadcast_short_claim' if stage == 'complete' else 'refund_local_leg')
    assert recovered[0][1]['secret_exposed'] == initial[1]['secret_exposed']
    pair.restart('alice')
    assert saved_snapshot(pair) == recovered
    store, journal, _, _ = pair.nodes['alice']
    assert journal.operations(pair.sid) == operations
    assert store.db.execute(
        'SELECT state,cost FROM reservations WHERE id=?',
        (initial[1]['reservation_id'],)
    ).fetchone() == reservation
    assert len(pair.a.records) == 1
    assert len(pair.b.records) == (1 if stage == 'complete' else 0)
    assert store.verify_audit()


@pytest.mark.parametrize('change', ['error', 'canonical', 'reference', 'new_field'])
def test_terminal_journal_keeps_meaningful_changes(terminal_pair, change):
    pair = terminal_pair
    journal = pair.nodes['alice'][1]
    rev, state = journal.load(pair.sid)
    candidate = deepcopy(state)
    if change == 'error':
        candidate['last_error'] = {'code': 'RPC', 'message': 'Observation unavailable'}
    elif change == 'canonical':
        candidate['observations']['a']['canonical'] = False
    elif change == 'reference':
        candidate['refs']['a'] = {'txid': 'ab' * 32, 'vout': 0}
    else:
        candidate['recovery_marker'] = 'new durable information'
    assert journal.save(pair.sid, candidate, rev) == rev + 1
    pair.restart('alice')
    journal = pair.nodes['alice'][1]
    assert journal.load(pair.sid) == (rev + 1, candidate)
    with pytest.raises(SwapError, match='REVISION_CONFLICT'):
        journal.save(pair.sid, state, rev)
    if candidate['secret_exposed']:
        candidate['secret_exposed'] = False
        with pytest.raises(SwapError, match='SECRET_ROLLBACK'):
            journal.save(pair.sid, candidate, rev + 1)


def test_active_journal_revision_contract_is_unchanged(pair):
    pair.start()
    journal = pair.nodes['alice'][1]
    rev, state = journal.load(pair.sid)
    assert state['stage'] == 'proposed'
    assert journal.save(pair.sid, state, rev) == rev + 1


def test_terminal_poll_still_checks_evm_withdrawal(pair, monkeypatch):
    pair.start()
    for _ in range(18):
        pair.step()
    coordinator = pair.nodes['alice'][3]
    pair.nodes['alice'][3].tick()
    incoming = coordinator.drivers[B]
    # Component control for the EVM withdrawal callback, without a real EVM.
    monkeypatch.setattr(incoming, 'family', 'evm')
    coordinator.policy = replace(coordinator.policy, require_evm_finalized=False)
    ready = [True]
    calls = []
    def withdrawal(*args, **kwargs):
        calls.append(kwargs['refund'])
        return ready[0]
    monkeypatch.setattr(incoming, 'ensure_withdrawal', withdrawal, raising=False)
    initial = saved_snapshot(pair)
    coordinator.tick()
    coordinator.tick()
    assert calls == [False, False]
    assert saved_snapshot(pair) == initial
    ready[0] = False
    coordinator.tick()
    assert pair.state('alice')['stage'] == 'withdrawing'


def test_terminal_poll_clears_persisted_error(terminal_pair):
    pair = terminal_pair
    journal = pair.nodes['alice'][1]
    rev, state = journal.load(pair.sid)
    state['last_error'] = {'code': 'RPC', 'message': 'Previous observation failed'}
    journal.save(pair.sid, state, rev)
    pair.restart('alice')
    before = saved_snapshot(pair)
    pair.nodes['alice'][3].tick()
    cleared = saved_snapshot(pair)
    assert cleared[0][0] == before[0][0] + 1
    assert cleared[0][1]['last_error'] is None
    pair.restart('alice')
    assert saved_snapshot(pair) == cleared
    pair.nodes['alice'][3].tick()
    assert saved_snapshot(pair) == cleared
