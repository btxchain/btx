"""Exercise the embedded Python startup policy with disposable state."""
import json

import pytest

from swapnet import embedded
from swapnet.errors import RPCConnectionRefused, RPCTransportTimeout, SwapError
from swapnet.journal import Journal
from swapnet.store import Store


NETWORK = '11' * 32
BITCOIN_GENESIS = '22' * 32
BTC = 'btc:' + BITCOIN_GENESIS + ':0:native'
RPC_URL = 'http://127.0.0.1:18443'


@pytest.fixture
def bitcoin_rpc(monkeypatch):
    calls = []
    wallets = ['funding wallet']
    fault = None

    class BitcoinRPC:
        def __init__(self, url=RPC_URL, *, cookie_path=None, timeout=10):
            self.url, self.cookie_path, self.timeout = url, cookie_path, timeout

        def __call__(self, method, *params):
            calls.append((self.url, method, params))
            if (method, params) == ('getblockchaininfo', ()):
                if fault:
                    raise fault()
                return {'chain': 'regtest'}
            if (method, params) == ('getblockhash', (0,)):
                return BITCOIN_GENESIS
            if (method, params) == ('listwallets', ()):
                return wallets
            pytest.fail(f'Unexpected Bitcoin RPC during startup: {method}')

    def set_fault(error):
        nonlocal fault
        fault = error

    monkeypatch.setattr(embedded, 'LocalRPC', BitcoinRPC)
    return BitcoinRPC, calls, set_fault, wallets


def open_host(path):
    def unexpected(*args):
        pytest.fail(f'Unexpected native callback during startup: {args}')
    return embedded.Host(json.dumps({
        'network': NETWORK, 'datadir': str(path), 'chain': 'regtest',
    }), unexpected, unexpected)


def test_explicit_bitcoin_outage_keeps_saved_policy_and_no_fallback(tmp_path, monkeypatch, bitcoin_rpc):
    directory = tmp_path / 'swapnet'
    directory.mkdir(mode=0o700)
    store = Store(directory / 'state.sqlite')
    policy = {'asset': BTC, 'rpc_url': RPC_URL, 'wallet': 'funding wallet'}
    Journal(store).set_setting('asset_policies', {BTC: policy})
    store.close()

    _, calls, set_fault, wallets = bitcoin_rpc
    wallets.append('other')
    set_fault(RPCConnectionRefused)

    def unexpected_discovery(*args):
        pytest.fail('Explicit Bitcoin binding must not fall back to discovery')

    monkeypatch.setattr(embedded, 'discover_bitcoin', unexpected_discovery)
    host = open_host(tmp_path)
    try:
        assert host.startup_errors == {BTC: 'RPC_UNAVAILABLE'}
        assert BTC not in host.drivers
        assert calls == [(RPC_URL, 'getblockchaininfo', ())]
        assert host.journal.setting('asset_policies', {}) == {BTC: policy}
    finally:
        host.close()

    set_fault(None)
    host = open_host(tmp_path)
    try:
        assert host.startup_errors == {}
        assert host.drivers[BTC].wallet.url == RPC_URL + '/wallet/funding%20wallet'
        assert host.journal.setting('asset_policies', {}) == {BTC: policy}
    finally:
        host.close()


def test_discovery_timeout_is_reported_and_clears_on_restart(tmp_path, monkeypatch, bitcoin_rpc):
    factory, calls, set_fault, _ = bitcoin_rpc
    set_fault(RPCTransportTimeout)
    monkeypatch.setattr(embedded, 'discover_bitcoin', lambda *args: factory())
    host = open_host(tmp_path)
    try:
        assert host.startup_errors == {'bitcoin_auto': 'RPC_UNAVAILABLE'}
        assert calls == [(RPC_URL, 'getblockchaininfo', ())]
        assert len(host.drivers) == 1
    finally:
        host.close()

    set_fault(None)
    host = open_host(tmp_path)
    try:
        assert host.startup_errors == {}
        assert host.drivers[BTC].wallet.url == RPC_URL + '/wallet/funding%20wallet'
    finally:
        host.close()


def test_bad_wrapping_key_fails_startup_without_replacing_it(tmp_path, monkeypatch):
    monkeypatch.setattr(embedded, 'discover_bitcoin', lambda *args: None)
    host = open_host(tmp_path)
    host.close()
    key = tmp_path / 'swapnet' / 'vault.key'
    original = key.read_bytes()
    key.write_bytes(b'wrong length')
    with pytest.raises(SwapError) as raised:
        open_host(tmp_path)
    assert raised.value.code == 'VAULT_FORMAT'
    assert key.read_bytes() == b'wrong length'
    key.write_bytes(original)
    host = open_host(tmp_path)
    try:
        assert host.startup_errors == {}
        assert key.read_bytes() == original
    finally:
        host.close()
