"""Adopt an existing HTLC output, and do not let junk sessions fill the journal."""
from decimal import Decimal
import os
from types import SimpleNamespace

import pytest

from swapnet.adapters import coin_string
from swapnet.canonical import atoms
from swapnet.drivers import UTXODriver
from swapnet.errors import SwapError
from swapnet.funding_scan import find_funding_output
from swapnet.journal import Journal, local_dump
from swapnet.store import Store
from test_execution_v2 import A, NETWORK, Driver, Ledger, Time, pair

TXID = "ab" * 32
OTHER = "cd" * 32
RAW = "ee" * 32


class Chain:
    def __init__(self, script, amount_atoms):
        self.script = script
        self.coin = Decimal(coin_string(atoms(amount_atoms)))
        self.unspents = []
        self.wallet_coins = []
        self.raw = {}
        self.fail = None

    def add(self, txid, vout, *, script=None, amount=None, wallet=False):
        coin = {"txid": txid, "vout": vout, "scriptPubKey": self.script if script is None else script,
                "amount": self.coin if amount is None else amount}
        (self.wallet_coins if wallet else self.unspents).append(coin)
        return coin

    def rpc(self, method, *args):
        if self.fail and method in self.fail:
            raise SwapError("CHAIN_RPC", "lookup failed")
        if method == "getdescriptorinfo":
            body = args[0]
            return {"checksum": "aaaaaaaa", "descriptor": body + "#aaaaaaaa"}
        if method == "scantxoutset":
            return {"success": True, "unspents": self.unspents}
        if method == "gettxout":
            txid, vout, _mempool = args
            for coin in self.unspents + self.wallet_coins:
                if coin["txid"] == txid and coin["vout"] == vout:
                    return {"scriptPubKey": {"hex": coin["scriptPubKey"]}, "value": coin["amount"]}
            return None
        if method == "getrawtransaction":
            raw = self.raw.get(args[0])
            if raw is None:
                raise SwapError("CHAIN_RPC", "missing")
            return {"txid": args[0], "hex": raw}
        raise SwapError("CHAIN_RPC", method)

    def wallet(self, method, *args):
        if method == "listunspent":
            return self.wallet_coins
        if method == "gettransaction":
            raw = self.raw.get(args[0])
            if raw is None:
                raise SwapError("CHAIN_RPC", "missing")
            return {"txid": args[0], "hex": raw}
        raise SwapError("CHAIN_RPC", method)


def utxo(chain):
    return UTXODriver(A, chain.rpc, chain.wallet, chain.wallet, None, None, network=NETWORK)


def terms(script, amount="10000"):
    return SimpleNamespace(lock_commitment=script, amount_atoms=amount)


class AdoptingDriver(UTXODriver):
    """Real UTXO driver type so the coordinator cannot skip the chain scan."""

    def __init__(self, inner, chain):
        super().__init__(inner.asset, chain.rpc, chain.wallet, chain.wallet, None, None, network=NETWORK)
        self.inner = inner
        self.funding_calls = 0

    def observe(self, leg, ref):
        return self.inner.observe(leg, ref)

    def clock(self):
        return self.inner.clock()

    def prepare_funding(self, *args, **kwargs):
        self.funding_calls += 1
        raise AssertionError("prepare_funding")

    def prepare_refund(self, *args, **kwargs):
        return self.inner.prepare_refund(*args, **kwargs)

    def watch_terms(self, *args, **kwargs):
        return self.inner.watch_terms(*args, **kwargs)

    def verify_terms(self, *args, **kwargs):
        return self.inner.verify_terms(*args, **kwargs)


def install(pair, chain):
    pair.start()
    pair.deliver()
    state = pair.state("alice")
    assert state["stage"] == "committed"
    assert not state["funding_prepared"]
    inner = pair.nodes["alice"][3].drivers[A]
    driver = AdoptingDriver(inner, chain)
    pair.nodes["alice"][3].drivers[A] = driver
    return driver, state["agreement"]["long_leg"]


def test_second_prepare_funding_not_called_when_output_exists(pair):
    chain = Chain("00", "1")
    driver, leg = install(pair, chain)
    chain.script = leg["lock_commitment"]
    chain.coin = Decimal(coin_string(atoms(leg["amount_atoms"])))
    chain.add(TXID, 1)
    alice = pair.nodes["alice"][3]
    alice.tick_one(pair.sid)
    alice.tick_one(pair.sid)
    assert driver.funding_calls == 0
    state = pair.state("alice")
    assert state["refs"]["a"] == {"txid": TXID, "vout": 1}
    assert state["funding_broadcast"] is True and state["recovery_ready"] is True
    assert state["stage"] == "funded"
    ops = pair.nodes["alice"][1].operations(pair.sid, private=True)
    assert [op["kind"] for op in ops] == ["refund"]
    assert ops[0]["metadata"]["reference"] == {"txid": TXID, "vout": 1}
    assert not pair.a.records


def test_lookup_failure_does_not_fund(pair):
    chain = Chain("00", "1")
    chain.fail = {"scantxoutset"}
    driver, _leg = install(pair, chain)
    with pytest.raises(SwapError, match="CHAIN_RPC"):
        pair.nodes["alice"][3].tick_one(pair.sid)
    assert driver.funding_calls == 0
    state = pair.state("alice")
    assert state["stage"] == "committed" and not state["funding_prepared"]
    assert pair.nodes["alice"][1].operations(pair.sid) == []
    assert not pair.a.records


def test_utxo_scan_matches_script_and_amount():
    script = "aa" * 32
    chain = Chain(script, "10000")
    chain.add(TXID, 2)
    found = find_funding_output(utxo(chain), terms(script))
    assert found == {"txid": TXID, "vout": 2}
    chain.raw[TXID] = RAW
    assert find_funding_output(utxo(chain), terms(script))["raw"] == RAW
    # A wallet-known mempool output is still an exact lock.
    chain.unspents.clear()
    chain.raw.clear()
    chain.add(OTHER, 0, wallet=True)
    assert find_funding_output(utxo(chain), terms(script)) == {"txid": OTHER, "vout": 0}
    chain.wallet_coins.clear()
    chain.add(TXID, 0, amount=Decimal("1"))
    assert find_funding_output(utxo(chain), terms(script)) is None
    chain.unspents.clear()
    chain.add(TXID, 0)
    chain.add(OTHER, 1)
    with pytest.raises(SwapError, match="FUNDING_AMBIGUOUS"):
        find_funding_output(utxo(chain), terms(script))


def test_utxo_driver_cannot_skip_the_scan():
    script = "bb" * 16
    chain = Chain(script, "10000")
    chain.add(TXID, 4)
    driver = utxo(chain)
    driver.scan_existing_funding = lambda _terms: {"txid": OTHER, "vout": 9}
    assert find_funding_output(driver, terms(script))["txid"] == TXID
    chain.fail = {"getdescriptorinfo"}
    with pytest.raises(SwapError, match="CHAIN_RPC"):
        find_funding_output(driver, terms(script))


def test_memory_double_without_scan_is_empty():
    driver = Driver(Ledger(A, Time()), "alice")
    assert find_funding_output(driver, terms("cc")) is None
    driver.scan_existing_funding = lambda _terms: {"txid": TXID, "vout": 3}
    assert find_funding_output(driver, terms("cc")) == {"txid": TXID, "vout": 3}

    class Bare:
        family = "btc"

    with pytest.raises(SwapError, match="FUNDING_LOOKUP"):
        find_funding_output(Bare(), terms("cc"))


def journal(tmp_path):
    os.chmod(tmp_path, 0o700)
    store = Store(tmp_path / "state.sqlite")
    return store, Journal(store)


def add_sessions(journal, stage, count, *, start=0, operation=False):
    with journal.store.transaction() as db:
        for n in range(start, start + count):
            sid = f"{n:064x}"
            db.execute(
                "INSERT INTO sn_negotiations VALUES(?,?,?,?,?,?)",
                (sid, 0, "p", "q", stage, local_dump({"stage": stage, "principal": "p", "peer": "q"})),
            )
            if operation:
                db.execute(
                    "INSERT INTO sn_operations VALUES(?,?,?,?,?,?,?,?)",
                    (sid, sid, "asset", "fund", "11" * 32, "aa", "prepared", local_dump({})),
                )


def test_cancelled_and_rejected_without_operations_do_not_count(tmp_path):
    store, book = journal(tmp_path)
    try:
        add_sessions(book, "cancelled", 4096)
        add_sessions(book, "rejected", 4096, start=5000)
        book.ensure_capacity()
        assert book.save("f" * 64, {"principal": "p", "peer": "q", "stage": "offered"}, -1) == 0
        assert store.db.execute("SELECT count(*) FROM sn_negotiations").fetchone()[0] == 8193
    finally:
        store.close()


def test_complete_and_refunded_sessions_still_count_and_stay(tmp_path):
    store, book = journal(tmp_path)
    try:
        add_sessions(book, "complete", 4095)
        add_sessions(book, "refunded", 1, start=6000)
        with pytest.raises(SwapError, match="SESSION_LIMIT"):
            book.ensure_capacity()
        with pytest.raises(SwapError, match="SESSION_LIMIT"):
            book.save("f" * 64, {"principal": "p", "peer": "q", "stage": "offered"}, -1)
        assert store.db.execute("SELECT count(*) FROM sn_negotiations WHERE stage='complete'").fetchone()[0] == 4095
        assert store.db.execute("SELECT count(*) FROM sn_negotiations WHERE stage='refunded'").fetchone()[0] == 1
    finally:
        store.close()


def test_cancelled_session_with_an_operation_still_counts(tmp_path):
    store, book = journal(tmp_path)
    try:
        add_sessions(book, "cancelled", 4096, operation=True)
        with pytest.raises(SwapError, match="SESSION_LIMIT"):
            book.ensure_capacity()
        assert store.db.execute("SELECT count(*) FROM sn_negotiations").fetchone()[0] == 4096
        assert store.db.execute("SELECT count(*) FROM sn_operations").fetchone()[0] == 4096
    finally:
        store.close()


def test_active_session_cap_stays_128(tmp_path):
    store, book = journal(tmp_path)
    try:
        add_sessions(book, "cancelled", 200)
        add_sessions(book, "offered", 127, start=1000)
        book.ensure_capacity()
        add_sessions(book, "committed", 1, start=2000)
        with pytest.raises(SwapError, match="ACTIVE_LIMIT"):
            book.ensure_capacity()
        assert store.db.execute("SELECT count(*) FROM sn_negotiations WHERE stage='offered'").fetchone()[0] == 127
    finally:
        store.close()
