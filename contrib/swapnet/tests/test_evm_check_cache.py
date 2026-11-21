"""EVMAdapter.check_chain: chain identity, contract code and sync state are re-read on an interval, after any
failure and always in full before a broadcast. A failed forced check drops the previous success. The code at a
finalized block hash is read once; a replaced block number is read again."""
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


def test_a_failed_forced_check_drops_the_cached_success():
    rpc, clock = Rpc(), [1000.0]
    a = adapter(rpc, clock)
    a.check_chain()
    rpc.chain_id = 9
    with pytest.raises(SwapError):
        a.check_chain(force=True)
    rpc.chain_id = 1
    before = len(rpc.calls)
    a.check_chain()
    assert "eth_chainId" in rpc.calls[before:]


def _word(raw):
    return raw.rjust(32, b"\x00")


class ObserveRpc(Rpc):
    def __init__(self):
        super().__init__()
        self.block_hash = "aa" * 32
        self.code = CODE
        self.view = (
            bytes.fromhex("ab" * 32)
            + _word(bytes.fromhex("11" * 20))
            + _word(bytes.fromhex("22" * 20))
            + _word(bytes.fromhex("33" * 20))
            + _word((1).to_bytes(1, "big"))
            + _word((600_000_000).to_bytes(4, "big"))
            + _word((1).to_bytes(1, "big"))
        )

    def __call__(self, method, *params):
        self.calls.append((method, params[1] if len(params) > 1 else None))
        if method == "eth_getBlockByNumber" and params[0] != "0x0":
            return {"hash": "0x" + self.block_hash, "number": "0x10"}
        if method == "eth_getCode" and params and params[0] != "latest":
            return "0x" + self.code.hex()
        if method == "eth_call":
            return "0x" + self.view.hex()
        return super().__call__(method, *params)


def test_a_replaced_finalized_block_rechecks_its_code():
    rpc, clock = ObserveRpc(), [1000.0]
    a = adapter(rpc, clock)
    expected = {"hashlock": "ab" * 32, "token": "0x" + "11" * 20, "refund_to": "0x" + "22" * 20,
                "claim_to": "0x" + "33" * 20, "amount": 1, "refund_at": 600_000_000}
    def historical_code(calls):
        return [c for c in calls if isinstance(c, tuple) and c[0] == "eth_getCode" and c[1] not in (None, "latest")]
    a.observe("cd" * 32, expected, 1)
    assert len(historical_code(rpc.calls)) == 1
    a.observe("cd" * 32, expected, 2)
    assert len(historical_code(rpc.calls)) == 1  # same block hash
    rpc.block_hash = "bb" * 32
    rpc.code = b"\x00" * len(CODE)
    with pytest.raises(SwapError, match="CONTRACT_CODE"):
        a.observe("cd" * 32, expected, 3)
