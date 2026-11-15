"""EVMAdapter.check_chain: chain identity, contract code and sync state are re-read on an interval, after any
failure and always in full before a broadcast; the code at a finalized block is read once."""
import pytest

from swapnet.errors import SwapError
from swapnet.evm import EVMAdapter, keccak256

GENESIS = "11" * 32
CODE = bytes.fromhex("6080604052") * 4
CONTRACT = "0x" + "c0" * 20


class Rpc:
    def __init__(self):
        self.calls = []
        self.syncing = False
        self.chain_id = 1

    def __call__(self, method, *params):
        self.calls.append(method)
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            if params[0] == "0x0":
                return {"hash": "0x" + GENESIS}
            return {"hash": "0x" + "22" * 32, "number": "0x10"}
        if method == "eth_syncing":
            return self.syncing
        if method == "eth_getCode":
            return "0x" + CODE.hex()
        if method == "eth_sendRawTransaction":
            return "0x" + keccak256(bytes.fromhex(params[0][2:])).hex()
        raise AssertionError(method)


def adapter(rpc, clock):
    return EVMAdapter(rpc, GENESIS, 1, CONTRACT, keccak256(CODE).hex(), monotonic=lambda: clock[0])


def test_identity_and_sync_are_cached_between_intervals():
    rpc, clock = Rpc(), [1000.0]
    a = adapter(rpc, clock)
    a.check_chain()
    assert len(rpc.calls) == 4
    a.check_chain()
    assert len(rpc.calls) == 4  # nothing re-read
    clock[0] += EVMAdapter.SYNC_TTL
    a.check_chain()
    assert rpc.calls[4:] == ["eth_syncing"]
    clock[0] += EVMAdapter.IDENTITY_TTL
    a.check_chain()
    assert sorted(rpc.calls[5:]) == sorted(["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_syncing"])


def test_a_broadcast_always_checks_in_full():
    rpc, clock = Rpc(), [1000.0]
    a = adapter(rpc, clock)
    a.check_chain()
    before = len(rpc.calls)
    a.broadcast(b"\x02\x01")
    assert rpc.calls[before:] == ["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_syncing",
                                  "eth_sendRawTransaction"]


def test_a_failure_is_not_cached():
    rpc, clock = Rpc(), [1000.0]
    a = adapter(rpc, clock)
    rpc.chain_id = 5
    with pytest.raises(SwapError):
        a.check_chain()
    rpc.chain_id = 1
    a.check_chain()  # re-checked right away, now fine
    rpc.syncing = {"currentBlock": "0x1"}
    clock[0] += EVMAdapter.SYNC_TTL
    with pytest.raises(SwapError):
        a.check_chain()
    with pytest.raises(SwapError):
        a.check_chain()  # still syncing: the failed check was not cached
