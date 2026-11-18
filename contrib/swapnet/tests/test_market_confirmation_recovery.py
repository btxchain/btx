"""Public confirmation retry: real SQLite/signed messages, simulated chains."""
from copy import deepcopy
from dataclasses import asdict
import sqlite3

import pytest

from swapnet.authorization import Principal
from swapnet.canonical import digest, dumps, loads
from swapnet.errors import SwapError
from swapnet.market_application import Application
from swapnet.policy import Mandate, SafetyPolicy
from swapnet.store import Store
from swapnet.vault import ForeignKeyVault
from test_execution_v2 import A, B, NETWORK, Driver, Identity, Ledger, Time
from test_initial_proposal_retry import no_fresh_setup, proposal_packets, snapshot


@pytest.fixture
def market_apps(tmp_path):
    time = Time()
    ledgers = {asset: Ledger(asset, time) for asset in (A, B)}
    nodes, wire = {}, []
    for name in ('alice', 'bob'):
        folder = tmp_path / name
        folder.mkdir(mode=0o700)
        nodes[name] = Application(
            Store(folder / 'state.sqlite'), NETWORK, Identity(name),
            ForeignKeyVault(folder / 'foreign-vault.json', b'1' * 32),
            {asset: Driver(ledger, name) for asset, ledger in ledgers.items()},
            lambda peer, command, raw, sender=name: (wire.append((sender, command, raw)) or True),
            clock=time, policy=SafetyPolicy(btx_confirmations=2, btc_confirmations=2,
                settlement_margin_seconds=10, reveal_margin_seconds=10))
    nodes['bob'].rpc(Principal('bob', True, 'wallet'), 'setswapmode', {'mode': 'maker'})
    for app in nodes.values():
        app.peer_connected(1)

    def deliver():
        count = 0
        while wire:
            sender, command, raw = wire.pop(0)
            nodes['bob' if sender == 'alice' else 'alice'].on_message(1, command, raw)
            count += 1
            assert count < 256

    def step():
        deliver()
        for app in nodes.values():
            app.tick()
        deliver()
        time.n += 1

    yield nodes, time, ledgers, wire, deliver, step
    for app in nodes.values():
        app.close()


OWNER = Principal('alice', True, 'wallet')


def preview(apps):
    nodes, time, _, _, deliver, step = apps
    alice, bob = nodes['alice'], nodes['bob']
    owner = Principal('bob', True, 'wallet')
    mid = bob.rpc(owner, 'createswapmandate', {'mandate': asdict(Mandate(
        'bob', B, '10000000', '100000', '1000', time() + 10000, '66' * 32))})['mandate_id']
    bob.rpc(owner, 'setswapmarket', {'market': {
        'sell_asset': A, 'buy_asset': B, 'numerator': '2', 'denominator': '1',
        'maker_fee_atoms': '10', 'max_receive_network_fee_atoms': '100',
        'max_input_atoms': '100000', 'expires_at': time() + 10000},
        'mandate_id': mid, 'max_local_fee_atoms': '500',
        'refund_fee_atoms': '100', 'claim_fee_atoms': '100'})
    offer = bob.rpc(owner, 'publishswapoffer', {'sell_asset': A, 'buy_asset': B,
        'sizes': ['10000'], 'kind': 'firm', 'slots': 1, 'ttl': 300})['offer']
    for _ in range(3):
        step()
    assert offer in alice.rpc(OWNER, 'listswappublicoffers')['offers']
    body = offer['body']
    request = alice.rpc(OWNER, 'requestpublicswapquote', {
        'provider': body['provider'], 'offer_id': body['offer_id'], 'tier': 0})
    for _ in range(4):
        step()
    quote, = alice.rpc(OWNER, 'getswapquotes', {'request_id': request['request_id']})['quotes']
    result = alice.rpc(OWNER, 'previewswap', {'quote_id': quote['id'],
        'max_local_fee_atoms': '500', 'refund_fee_atoms': '100', 'claim_fee_atoms': '100'})
    assert result['funds_reserved'] is False
    assert not alice.store.db.execute('SELECT id FROM reservations').fetchall()
    return result['preview_id']


def confirm(app, token, ctx=OWNER):
    return app.rpc(ctx, 'confirmswap', {'preview_id': token})


def install_fault(app):
    app.store.db.execute("""CREATE TRIGGER reject_proposal BEFORE INSERT ON sn_outbox
        WHEN json_extract(CAST(NEW.body AS TEXT),'$.body.kind')='proposal'
        BEGIN SELECT RAISE(ABORT,'proposal fault'); END""")


def missing_proposal(apps):
    token = preview(apps)
    alice = apps[0]['alice']
    install_fault(alice)
    with pytest.raises(sqlite3.IntegrityError, match='proposal fault'):
        confirm(alice, token)
    sid, = alice.store.db.execute('SELECT id FROM sn_negotiations').fetchone()
    assert snapshot(alice, sid)['budgets'] == [['10500', '0']]
    assert not proposal_packets(alice)
    alice.store.db.execute('DROP TRIGGER reject_proposal')
    return token, sid


def reopen(apps):
    nodes, time, ledgers, wire, deliver, _ = apps
    old = nodes['alice']
    path, identity, policy = old.vault.path, old.identity, old.coordinator.policy
    old.close()
    nodes['alice'] = Application(Store(path.parent / 'state.sqlite'), NETWORK, identity,
        ForeignKeyVault(path, b'1' * 32),
        {asset: Driver(ledger, 'alice') for asset, ledger in ledgers.items()},
        lambda peer, command, raw: (wire.append(('alice', command, raw)) or True),
        clock=time, policy=policy)
    nodes['alice'].peer_connected(1)
    deliver()
    return nodes['alice']


def assert_delivered(apps, sid):
    nodes, time, ledgers, _, deliver, _ = apps
    alice = nodes['alice']
    packets = proposal_packets(alice)
    assert len(packets) == 1, 'Confirmation must restore the missing original proposal'
    original = alice.journal.load(sid)[1]['proposal']
    assert packets[0]['body']['payload'] == original
    for mid, recipient, command, packet, _ in alice.journal.due(time()):
        if packet['body']['kind'] == 'proposal' and packet['body']['swap_id'] == sid:
            alice._route(recipient, command, packet)
            alice.journal.sent(mid, time())
    deliver()  # No financial tick after negotiation has advanced.
    maker = nodes['bob'].journal.load(sid)[1]
    assert maker['stage'] == 'offered' and maker['proposal'] == original
    assert all(not ledger.records and not ledger.transactions for ledger in ledgers.values())
    assert all(not app.journal.operations(sid) for app in nodes.values())


@pytest.mark.parametrize('reopened', [False, True])
def test_confirmation_recovers_original_proposal(market_apps, monkeypatch, reopened):
    token, sid = missing_proposal(market_apps)
    alice = market_apps[0]['alice']
    before = snapshot(alice, sid)
    if reopened:
        alice = reopen(market_apps)
    no_fresh_setup(alice, monkeypatch)
    result = confirm(alice, token)
    assert result['swap_id'] == sid and result['stage'] == 'proposed'
    assert snapshot(alice, sid) == before
    assert_delivered(market_apps, sid)
    assert snapshot(alice, sid) == before


@pytest.mark.parametrize('mode', ['normal', 'not_due', 'acknowledged', 'preview_write', 'expired_envelope'])
def test_confirmation_deduplicates_existing_proposal(market_apps, monkeypatch, mode):
    token = preview(market_apps)
    alice = market_apps[0]['alice']
    if mode == 'preview_write':
        alice.store.db.execute("""CREATE TRIGGER reject_preview BEFORE UPDATE OF swap_id ON sn_trade_previews
            BEGIN SELECT RAISE(ABORT,'preview fault'); END""")
        with pytest.raises(sqlite3.IntegrityError, match='preview fault'):
            confirm(alice, token)
        alice.store.db.execute('DROP TRIGGER reject_preview')
        sid, = alice.store.db.execute('SELECT id FROM sn_negotiations').fetchone()
        alice = reopen(market_apps)
    else:
        sid = confirm(alice, token)['swap_id']
    packet, = proposal_packets(alice)
    mid = digest('BTX/SWAPNET/PACKET/2', packet)
    if mode == 'not_due':
        alice.store.db.execute('UPDATE sn_outbox SET next_try=? WHERE id=?', (market_apps[1]() + 10000, mid))
    elif mode == 'acknowledged':
        alice.journal.ack(mid, 'bob')
    # Expired quote/mandate, but the original 600-second envelope is still live.
    market_apps[1].n += 1000 if mode == 'expired_envelope' else 100
    before = snapshot(alice, sid)
    queued = alice.store.db.execute('SELECT * FROM sn_outbox ORDER BY id').fetchall()
    seq = alice.store.db.execute('SELECT * FROM sn_sequences ORDER BY identity').fetchall()
    no_fresh_setup(alice, monkeypatch)
    def forbidden(*args, **kwargs):
        pytest.fail('An existing proposal was signed again')
    monkeypatch.setattr(alice.identity, 'sign', forbidden)
    for _ in range(2):
        if mode == 'expired_envelope':
            with pytest.raises(SwapError, match='QUOTE_EXPIRED'):
                confirm(alice, token)
        else:
            assert confirm(alice, token)['swap_id'] == sid
    assert snapshot(alice, sid) == before
    assert alice.store.db.execute('SELECT * FROM sn_outbox ORDER BY id').fetchall() == queued
    assert alice.store.db.execute('SELECT * FROM sn_sequences ORDER BY identity').fetchall() == seq


def test_expired_preview_can_retry_original_live_authority(market_apps):
    token, sid = missing_proposal(market_apps)
    alice = market_apps[0]['alice']
    expiry, = alice.store.db.execute('SELECT expires FROM sn_trade_previews WHERE id=?', (token,)).fetchone()
    market_apps[1].n = expiry
    before = snapshot(alice, sid)
    confirm(alice, token)
    assert snapshot(alice, sid) == before
    assert_delivered(market_apps, sid)


@pytest.mark.parametrize('failure,code', [
    ('quote_expired', 'QUOTE_EXPIRED'),
    ('revoked', 'MANDATE_EXPIRED'), ('restored', 'RECOVERY_READ_ONLY'),
    ('financial', 'RECOVERY_CONFLICT'), ('closed', 'RESERVATION')])
def test_missing_proposal_preserves_recovery_fences(market_apps, failure, code):
    token, sid = missing_proposal(market_apps)
    alice, time = market_apps[0]['alice'], market_apps[1]
    rev, state = alice.journal.load(sid)
    if failure == 'quote_expired':
        time.n = state['quote']['quote']['expires_at']
        body, = alice.store.db.execute('SELECT body FROM mandates').fetchone()
        # This public one-shot mandate expires with the quote. Verification
        # correctly stops at quote expiry first; independent mandate expiry
        # is covered through #816's accept/resume entry points.
        assert time() >= loads(body)['expires_at']
    elif failure == 'revoked':
        alice.store.db.execute('UPDATE mandates SET revoked=1')
    elif failure == 'restored':
        alice.journal.set_setting('restored_session:' + sid, True)
    elif failure == 'financial':
        state['funding_prepared'] = True
        alice.journal.save(sid, state, rev)
    else:
        alice.store.db.execute("UPDATE reservations SET state='closed'")
    before = snapshot(alice, sid)
    with pytest.raises(SwapError, match=code):
        confirm(alice, token)
    assert snapshot(alice, sid) == before and not proposal_packets(alice)


@pytest.mark.parametrize('ctx', [Principal('other', True, 'wallet'), Principal('alice', True, 'other')])
def test_wrong_preview_context_cannot_recover(market_apps, ctx):
    token, sid = missing_proposal(market_apps)
    alice = market_apps[0]['alice']
    before = snapshot(alice, sid)
    with pytest.raises(SwapError, match='FORBIDDEN'):
        confirm(alice, token, ctx)
    assert snapshot(alice, sid) == before and not proposal_packets(alice)


@pytest.mark.parametrize('stage', ['committed', 'funded', 'complete', 'refunded', 'cancelled'])
def test_progressed_confirmation_remains_read_only(market_apps, monkeypatch, stage):
    token, sid = missing_proposal(market_apps)
    alice = market_apps[0]['alice']
    rev, state = alice.journal.load(sid)
    state['stage'] = stage  # Status-only control, not a funded-chain qualification.
    alice.journal.save(sid, state, rev)
    market_apps[1].n += 1000
    before = snapshot(alice, sid)
    saved = alice.journal.load(sid)
    def forbidden(*args, **kwargs):
        pytest.fail('Confirmation retry advanced a progressed trade')
    monkeypatch.setattr(alice.coordinator, 'tick_one', forbidden)
    monkeypatch.setattr(alice.identity, 'sign', forbidden)
    for driver in alice.drivers.values():
        monkeypatch.setattr(driver, 'ready', forbidden)
        monkeypatch.setattr(driver, 'clock', forbidden)
    no_fresh_setup(alice, monkeypatch)
    expected = alice.coordinator.get(OWNER, sid)
    assert confirm(alice, token) == expected
    assert snapshot(alice, sid) == before and not proposal_packets(alice)
    assert alice.journal.load(sid) == saved


@pytest.mark.parametrize('failure', ['enqueue', 'sign'])
def test_repeat_failure_then_same_confirmation_recovers(market_apps, monkeypatch, failure):
    token, sid = missing_proposal(market_apps)
    alice = market_apps[0]['alice']
    before = snapshot(alice, sid)
    original = alice.identity.sign
    if failure == 'enqueue':
        install_fault(alice)
    else:
        def refused(*args):
            raise SwapError('TEST_SIGN', 'Temporary envelope signer refusal')
        monkeypatch.setattr(alice.identity, 'sign', refused)
    with pytest.raises((sqlite3.IntegrityError, SwapError)):
        confirm(alice, token)
    assert snapshot(alice, sid) == before and not proposal_packets(alice)
    if failure == 'enqueue':
        alice.store.db.execute('DROP TRIGGER reject_proposal')
    else:
        monkeypatch.setattr(alice.identity, 'sign', original)
    alice = reopen(market_apps)
    no_fresh_setup(alice, monkeypatch)
    confirm(alice, token)
    assert snapshot(alice, sid) == before
    assert_delivered(market_apps, sid)


def test_conflicting_proposal_is_not_overwritten(market_apps):
    token, sid = missing_proposal(market_apps)
    alice = market_apps[0]['alice']
    proposal = deepcopy(alice.journal.load(sid)[1]['proposal'])
    proposal['nonce'] = '99' * 32
    alice.emit('bob', 'proposal', sid, proposal)
    before = snapshot(alice, sid)
    queued = alice.store.db.execute('SELECT * FROM sn_outbox ORDER BY id').fetchall()
    with pytest.raises(SwapError, match='RECOVERY_CONFLICT'):
        confirm(alice, token)
    assert snapshot(alice, sid) == before
    assert alice.store.db.execute('SELECT * FROM sn_outbox ORDER BY id').fetchall() == queued
