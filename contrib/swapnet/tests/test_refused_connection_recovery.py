"""Local RPC transport + durable coordinator recovery; chain/signing are doubles."""
from contextlib import contextmanager
from dataclasses import replace
import json
import socket
import threading
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import pytest
from swapnet.errors import SwapError
from swapnet.rpcclient import LocalRPC
from test_execution_v2 import Pair, A, B


def identities(p):
    return [(o['id'], o['txid'], o['raw'])
            for o in p.nodes['alice'][1].operations(p.sid, private=True)]


@contextmanager
def funded_pair(path):
    path.mkdir(mode=0o700)
    p = Pair(path)
    try:
        p.start(); p.deliver()
        c = p.nodes['alice'][3]
        c.tick_one(p.sid); c.tick_one(p.sid); p.a.mine(3)
        s = p.state('alice')
        p.a.height = s['agreement']['long_leg']['lock_value']
        assert s['stage'] == 'funded' and s['recovery_ready']
        assert s['funding_broadcast'] and not s['secret_exposed'] and not s['refs'].get('b')
        yield p
    finally:
        for name in p.nodes:
            p.close(name)


@contextmanager
def refused_client(path, missing=False):
    cookie = path / '.cookie'
    if not missing:
        cookie.write_text('test:disposable'); cookie.chmod(0o600)
    # Release a locally chosen port: a bound non-listening socket times out on
    # Darwin. Verify the actual exception rather than assuming the OS outcome.
    with socket.socket() as guard:
        guard.bind(('127.0.0.1', 0))
        port = guard.getsockname()[1]
    client = LocalRPC('http://127.0.0.1:' + str(port), cookie_path=cookie, timeout=1)
    with pytest.raises(SwapError) as error:
        client('getblockcount')
    if not missing:
        assert isinstance(error.value.__cause__, urllib.error.URLError)
        assert isinstance(error.value.__cause__.reason, ConnectionRefusedError)
    else:
        assert error.value.code == 'RPC_COOKIE'
    yield client


def wire(p, client):
    c = p.nodes['alice'][3]
    local, foreign = c.drivers[A], c.drivers[B]
    clock, observe = foreign.clock, foreign.observe
    def checked_clock():
        client('getblockcount'); return clock()
    def checked_observe(*args):
        client('getblockcount'); return observe(*args)
    foreign.clock, foreign.observe = checked_clock, checked_observe
    s = p.state('alice'); ref = dict(s['refs']['a'])
    script = s['agreement']['long_leg']['lock_commitment']
    def local_rpc(method, *args):
        if method == 'gettxout':
            assert args[:2] == (ref['txid'], ref['vout'])
            return ({'bestblock': 'tip', 'scriptPubKey': {'hex': script}}
                    if p.a.records[ref['txid']]['state'] == 'locked' else None)
        if method == 'getbestblockhash': return 'tip'
        if method == 'getrawtransaction': return {'confirmations': p.a.records[ref['txid']]['confirmations']}
        raise AssertionError(method)
    local.rpc = local_rpc
    def no_funding(*args, **kwargs): raise AssertionError('New funding attempted')
    for driver in c.drivers.values(): driver.prepare_funding = no_funding
    return c


@pytest.mark.parametrize('missing_cookie', [False, True])
def test_mature_original_refund_recovers_across_reopen(tmp_path, missing_cookie):
    with funded_pair(tmp_path / 'pair') as p, refused_client(tmp_path, missing_cookie) as client:
        original = identities(p)
        c = wire(p, client)
        c.tick()
        assert p.state('alice')['stage'] == 'refund_broadcast'
        p.restart('alice'); c = wire(p, client)
        c.tick()  # already-known original refund: do not create another
        assert p.state('alice')['stage'] == 'refund_broadcast'
        p.a.mine(2); c.tick()
        assert p.state('alice')['stage'] == 'refunded'
        p.restart('alice'); c = wire(p, client); c.tick()
        assert p.state('alice')['stage'] == 'refunded'
        assert identities(p) == original
        assert len(p.a.records) == 1 and not p.b.records
        assert not p.state('alice')['secret_exposed']
        assert all(p.nodes[n][0].verify_audit() for n in p.nodes)
        refund = next(o for o in p.nodes['alice'][1].operations(p.sid, private=True) if o['kind'] == 'refund')
        assert p.a.transactions[refund['txid']] == refund['raw']


def test_real_connection_refusal_classification(tmp_path):
    with refused_client(tmp_path) as client, pytest.raises(SwapError) as error:
        client('getblockcount')
    assert error.value.code == 'RPC_UNAVAILABLE'
    assert type(error.value).__name__ == 'RPCConnectionRefused'
    assert set(error.value.as_dict()) == {'code', 'message'}
    assert isinstance(error.value.__cause__, urllib.error.URLError)
    assert isinstance(error.value.__cause__.reason, ConnectionRefusedError)


@pytest.mark.parametrize('kind', ['auth', 'json', 'chain', 'id', 'result', 'redirect'])
def test_actual_http_errors_never_authorize_refund(tmp_path, kind):
    class Response(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            status = 401 if kind == 'auth' else 302 if kind == 'redirect' else 500 if kind == 'chain' else 200
            obj = {'id': 'swapnet', 'result': 100, 'error': None}
            if kind == 'chain': obj['error'] = {'code': -1, 'message': 'Refused by chain'}
            if kind == 'id': obj['id'] = 'wrong'
            if kind == 'result': del obj['result']
            body = b'invalid JSON' if kind == 'json' else json.dumps(obj).encode()
            self.send_response(status)
            if kind == 'redirect': self.send_header('Location', '/redirect')
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Response)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    client = LocalRPC('http://127.0.0.1:' + str(server.server_port), timeout=1)
    try:
        with pytest.raises(SwapError) as error: client('getblockcount')
        assert type(error.value) is SwapError
        with funded_pair(tmp_path / 'pair') as p:
            original = identities(p); c = wire(p, client); c.tick()
            assert p.state('alice')['stage'] == 'funded'
            assert p.state('alice')['last_error']['code'] == error.value.code
            assert identities(p) == original and len(p.a.transactions) == 1
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


@pytest.mark.parametrize('reason', [ConnectionResetError(), 'connection refused'])
def test_unqualified_transport_errors_remain_generic(tmp_path, reason):
    client = LocalRPC('http://127.0.0.1:1', timeout=1)
    class Broken:
        def open(self, *args, **kwargs): raise urllib.error.URLError(reason)
    client.opener = Broken()
    with pytest.raises(SwapError) as error: client('getblockcount')
    assert type(error.value) is SwapError and error.value.code == 'RPC_UNAVAILABLE'


def test_generic_unavailable_code_is_not_permission(tmp_path):
    def client(*args): raise SwapError('RPC_UNAVAILABLE', 'Local chain client connection refused')
    with funded_pair(tmp_path / 'pair') as p:
        c = wire(p, client); c.tick()
        assert p.state('alice')['stage'] == 'funded'
        assert len(p.a.transactions) == 1


@pytest.mark.parametrize('guard', [
    'immature', 'incoming', 'secret', 'prior_conflict', 'not_ready', 'missing_refund',
    'noncanonical', 'wrong_terms', 'unconfirmed', 'claimed', 'stale',
    'wrong_reference', 'spent', 'wrong_tip', 'wrong_script'])
def test_refusal_preserves_local_refund_fences(tmp_path, guard):
    with funded_pair(tmp_path / 'pair') as p, refused_client(tmp_path) as client:
        c = wire(p, client); local = c.drivers[A]
        rev, s = c.journal.load(p.sid)
        if guard == 'immature': p.a.height -= 1
        elif guard == 'incoming': s['refs']['b'] = {'txid': '99' * 32, 'vout': 0}
        elif guard == 'secret': s['secret_exposed'] = True
        elif guard == 'prior_conflict': s['observations'] = {'b': {'conflicting': True}}
        elif guard == 'not_ready': s['recovery_ready'] = False
        elif guard == 'missing_refund': s['refund_op'] = None
        elif guard == 'wrong_reference': s['refs']['a']['vout'] += 1
        elif guard in {'noncanonical', 'wrong_terms', 'unconfirmed', 'claimed', 'stale'}:
            observe = local.observe
            def changed(*args):
                report = observe(*args)
                fields = {'noncanonical': {'canonical': False}, 'wrong_terms': {'exact_terms': False},
                          'unconfirmed': {'confirmations': 0}, 'claimed': {'claimed': True}}
                if guard == 'stale': return replace(report, clock=replace(report.clock, observed_at=p.time()-61))
                return replace(report, observation=replace(report.observation, **fields[guard]))
            local.observe = changed
        elif guard in {'spent', 'wrong_tip', 'wrong_script'}:
            rpc = local.rpc
            def changed_rpc(method, *args):
                value = rpc(method, *args)
                if method == 'gettxout':
                    if guard == 'spent': return None
                    if guard == 'wrong_tip': value['bestblock'] = 'old-tip'
                    if guard == 'wrong_script': value['scriptPubKey']['hex'] = '00'
                return value
            local.rpc = changed_rpc
        c._save(p.sid, s, rev)
        original = identities(p); c.tick()
        assert p.state('alice')['stage'] == 'funded'
        assert p.state('alice')['last_error'] is not None
        assert len(p.a.transactions) == 1 and identities(p) == original and not p.b.records
        assert p.a.records[s['refs']['a']['txid']]['state'] == 'locked'
