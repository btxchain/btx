"""Interrupted offline refund cleanup must resume without new spending authority."""
from dataclasses import replace
import pytest
from test_execution_v2 import A, B, pair
from swapnet.errors import SwapError
from swapnet.authorization import Principal

def offline(pair):
    c = pair.nodes['alice'][3]
    def unavailable(*args):
        raise SwapError('RPC_COOKIE', 'RPC cookie unavailable')
    c.drivers[B].observe = unavailable
    c.drivers[B].clock = unavailable
    c.drivers[A].rpc = lambda *args: {'confirmations': 2}
    return c

def reservation(pair):
    state = pair.state('alice')
    return pair.nodes['alice'][0].db.execute(
        'SELECT state FROM reservations WHERE id=?', (state['reservation_id'],)).fetchone()[0]

def refunded_observation(pair):
    pair.start()
    pair.deliver()
    c = pair.nodes['alice'][3]
    c.tick_one(pair.sid)
    c.tick_one(pair.sid)
    pair.deliver()
    agreement = pair.state('alice')['agreement']
    pair.a.height = agreement['long_leg']['lock_value']
    pair.b.height = agreement['short_leg']['lock_value']
    c.request_refund(Principal('alice'), pair.sid)
    pair.a.mine(2)
    return offline(pair)

@pytest.mark.parametrize('boundary', ['before_cleanup', 'during_transaction', 'after_cleanup'])
def test_offline_terminal_cleanup_retries_after_restart(pair, monkeypatch, boundary):
    c = refunded_observation(pair)
    store = pair.nodes['alice'][0]
    terminal, audit = c.authority.terminal, store._audit
    def interrupted(*args):
        if boundary == 'after_cleanup':
            terminal(*args)
        raise RuntimeError('injected cleanup interruption')
    def interrupted_audit(db, event):
        if event.get('type') == 'reservation_closed':
            raise RuntimeError('injected cleanup interruption')
        return audit(db, event)
    with monkeypatch.context() as m:
        if boundary == 'during_transaction':
            m.setattr(store, '_audit', interrupted_audit)
        else:
            m.setattr(c.authority, 'terminal', interrupted)
        with pytest.raises(RuntimeError, match='injected cleanup interruption'):
            c.tick_one(pair.sid)
    assert pair.state('alice')['stage'] == 'refunded'
    assert reservation(pair) == ('closed' if boundary == 'after_cleanup' else 'funded')
    operations = pair.nodes['alice'][1].operations(pair.sid)
    transactions = dict(pair.a.transactions)
    pair.restart('alice')
    c = offline(pair)
    c.tick_one(pair.sid)
    assert reservation(pair) == 'closed'
    db = pair.nodes['alice'][0].db
    budget = db.execute('SELECT held,used FROM mandates ORDER BY id').fetchall()
    assert all(held == '0' and int(used) > 0 for held, used in budget)
    assert db.execute('SELECT consumed FROM sn_grants').fetchall() == [(1,)]
    for _ in range(3):
        c.tick_one(pair.sid)
    assert db.execute('SELECT held,used FROM mandates ORDER BY id').fetchall() == budget
    assert pair.nodes['alice'][1].operations(pair.sid) == operations
    assert pair.a.transactions == transactions
    assert pair.nodes['alice'][0].verify_audit()

@pytest.mark.parametrize('change', [{'canonical': False}, {'confirmations': 0}])
def test_offline_cleanup_still_requires_confirmed_canonical_refund(pair, monkeypatch, change):
    c = refunded_observation(pair)
    rev, state = c.journal.load(pair.sid)
    state['stage'] = 'refunded'
    c.journal.save(pair.sid, state, rev)
    observe = c.drivers[A].observe
    def unqualified(*args):
        report = observe(*args)
        return replace(report, observation=replace(report.observation, **change))
    monkeypatch.setattr(c.drivers[A], 'observe', unqualified)
    with pytest.raises(SwapError, match='RPC cookie unavailable'):
        c.tick_one(pair.sid)
    assert reservation(pair) == 'funded'
