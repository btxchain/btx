"""Use real drivers and a durable journal with deterministic local RPC doubles."""
import pytest

from swapnet.drivers import UTXODriver
from swapnet.errors import RPCConnectionRefused, RPCTransportTimeout, SwapError
from swapnet.evm import keccak256
from swapnet.evm_driver import EVMDriver
from swapnet.journal import Journal
from swapnet.store import Store


GENESIS = '11' * 32
CONTRACT = '0x' + '22' * 20
RUNTIME = b'\x60'
SIGNED_BYTES = '02000000'


class ChainRPC:
    def __init__(self, family):
        self.family = family
        self.txid = ('0x' + keccak256(bytes.fromhex(SIGNED_BYTES)).hex()
                     if family == 'evm' else 'aa' * 32)
        self.present = False
        self.failure = None
        self.sends = []

    def __call__(self, method, *args):
        if method in {'getmempoolentry', 'eth_getTransactionByHash'}:
            if self.failure in {'refused', 'timeout'}:
                raise {'refused': RPCConnectionRefused, 'timeout': RPCTransportTimeout}[self.failure]()
            assert args == (self.txid,)
            if self.failure == 'malformed':
                return 'unexpected result'
            if self.failure == 'short':
                return {}
            if self.family == 'evm':
                return {'hash': self.txid} if self.present else None
            if self.present:
                return {'vsize': 20}
            raise SwapError('CHAIN_RPC', 'Not in mempool')
        if method in {'gettransaction', 'getrawtransaction'}:
            assert args == (self.txid, True)
            raise SwapError('CHAIN_RPC', 'Transaction not found')
        if method in {'sendrawtransaction', 'eth_sendRawTransaction'}:
            self.sends.append(args)
            expected = ('0x' if self.family == 'evm' else '') + SIGNED_BYTES
            assert args == (expected,)
            self.present = True
            if self.failure == 'lost_reply':
                raise RPCTransportTimeout()
            if self.failure == 'wrong_txid':
                return ('0x' if self.family == 'evm' else '') + 'bb' * 32
            return self.txid
        if method == 'eth_chainId':
            return '0x539'
        if method == 'eth_getBlockByNumber':
            assert args == ('0x0', False)
            return {'hash': '0x' + GENESIS}
        if method == 'eth_getCode':
            assert args == (CONTRACT, 'latest')
            return '0x' + RUNTIME.hex()
        if method == 'eth_syncing':
            return False
        pytest.fail(f'Unexpected RPC: {method}')


def driver_for(family, rpc, journal):
    if family == 'evm':
        return EVMDriver(f'evm:{GENESIS}:1337:native', rpc, journal, None,
                         CONTRACT, keccak256(RUNTIME).hex())
    return UTXODriver(f'btc:{GENESIS}:0:native', rpc, rpc, rpc, journal, None,
                      network='regtest')


@pytest.mark.parametrize('family', ['btc', 'evm'])
@pytest.mark.parametrize(
    ('failure', 'error_code', 'broadcast_reached'),
    [('refused', 'RPC_UNAVAILABLE', False), ('timeout', 'RPC_UNAVAILABLE', False),
     ('malformed', 'CHAIN_RESPONSE', False), ('short', 'CHAIN_RESPONSE', False),
     ('lost_reply', 'RPC_UNAVAILABLE', True), ('wrong_txid', 'TXID_MISMATCH', True)],
)
def test_broadcast_fault_retains_original_operation(tmp_path, family, failure,
                                                    error_code, broadcast_reached):
    path = tmp_path / 'state.sqlite'
    rpc = ChainRPC(family)
    store = Store(path)
    journal = Journal(store)
    driver = driver_for(family, rpc, journal)
    raw = ('0x' if family == 'evm' else '') + SIGNED_BYTES
    operation = journal.prepare('test-swap', driver.asset.id, 'refund', rpc.txid, raw)
    original = journal.operation(operation)
    try:
        rpc.failure = failure
        with pytest.raises(SwapError) as raised:
            journal.broadcast(operation, driver)
        assert raised.value.code == error_code
        assert journal.operation(operation) == original
        assert rpc.sends == ([(raw,)] if broadcast_reached else [])
    finally:
        store.close()

    rpc.failure = None
    store = Store(path)
    journal = Journal(store)
    try:
        assert journal.operations('test-swap', private=True) == [original]
        driver = driver_for(family, rpc, journal)
        assert journal.broadcast(operation, driver) == rpc.txid
        assert journal.broadcast(operation, driver) == rpc.txid
        assert journal.operations('test-swap', private=True) == [{**original, 'state': 'broadcast'}]
        assert rpc.sends == [(raw,)]
        assert store.verify_audit()
    finally:
        store.close()
