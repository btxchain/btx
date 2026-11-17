"""A missing native transaction is not a failed node call.

The embedded bridge raises LookupError('native-absent') only for the fixed
not-found RPC texts. Everything else stays NATIVE_RPC so a broadcast is not
retried over an unknown failure.
"""
import pytest
from swapnet.embedded import Host
from swapnet.errors import SwapError

TXID = 'ab' * 32

def host(fail):
    bridge = Host.__new__(Host)
    bridge.core_call = fail
    return bridge

def test_native_absence_is_a_chain_miss():
    def missing(*_args):
        raise LookupError('native-absent')
    with pytest.raises(SwapError) as caught:
        host(missing)._call('', 'getmempoolentry', [TXID])
    assert caught.value.code == 'CHAIN_RPC'

@pytest.mark.parametrize('exc', [
    LookupError('still indexing'),
    RuntimeError('Native operation rejected'),
    KeyError('native-absent'),
])
def test_other_native_failures_stay_failures(exc):
    def fail(*_args):
        raise exc
    with pytest.raises(SwapError) as caught:
        host(fail)._call('', 'getmempoolentry', [TXID])
    assert caught.value.code == 'NATIVE_RPC'
    assert 'native-absent' not in caught.value.message
    assert 'indexing' not in caught.value.message
