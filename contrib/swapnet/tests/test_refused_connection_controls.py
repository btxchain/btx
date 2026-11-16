"""Additional controls for the narrowly classified local refund recovery."""
from decimal import Decimal
import pytest
from swapnet.errors import SwapError
from swapnet.rpcclient import LocalRPC
from swapnet.terms import Agreement
from test_refused_connection_recovery import funded_pair, refused_client, wire, identities, A


def test_observation_only_stays_read_only(tmp_path):
    with funded_pair(tmp_path / 'pair') as p, refused_client(tmp_path) as client:
        c = wire(p, client)
        rev, s = c.journal.load(p.sid)
        s['recovery_facts'] = {'mode': 'observation_only',
            'agreement_id': Agreement.parse(s['agreement']).id, 'original': dict(s['refs']['a'])}
        c._save(p.sid, s, rev)
        rpc = c.drivers[A].rpc
        def valued_rpc(method, *args):
            result = rpc(method, *args)
            if method == 'gettxout' and result:
                result['value'] = Decimal(s['agreement']['long_leg']['amount_atoms']) / Decimal(100000000)
            return result
        c.drivers[A].rpc = valued_rpc
        before = identities(p)
        c.tick()
        after = p.state('alice')
        assert after['stage'] == 'funded'
        assert after['recovery_facts']['status'] == 'original_unspent'
        assert after['last_action'] == 'read_only_recovery'
        assert after['refs'] == s['refs'] and not after['secret_exposed']
        assert identities(p) == before and len(p.a.transactions) == 1
        assert all(p.nodes[n][0].verify_audit() for n in p.nodes)


@pytest.mark.parametrize('code,message', [
    ('RPC_COOKIE', 'RPC cookie permissions unsafe'),
    ('RPC_COOKIE', 'Malformed RPC cookie'),
    ('GENESIS_MISMATCH', 'Configured Bitcoin genesis differs'),
])
def test_other_cookie_and_network_errors_do_not_authorize(tmp_path, code, message):
    def broken(*args): raise SwapError(code, message)
    with funded_pair(tmp_path / 'pair') as p:
        c = wire(p, broken); before = identities(p); c.tick()
        assert p.state('alice')['stage'] == 'funded'
        assert p.state('alice')['last_error']['code'] == code
        assert identities(p) == before and len(p.a.transactions) == 1


def test_read_timeout_is_not_refusal():
    client = LocalRPC('http://127.0.0.1:1', timeout=1)
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, *args): raise TimeoutError('response timed out')
    class Opener:
        def open(self, *args, **kwargs): return Response()
    client.opener = Opener()
    with pytest.raises(SwapError) as error: client('getblockcount')
    assert type(error.value) is SwapError
    assert error.value.code == 'RPC_UNAVAILABLE'
