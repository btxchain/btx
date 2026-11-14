"""Adopt an existing HTLC output, and do not let junk sessions fill the journal."""
from dataclasses import asdict
from decimal import Decimal
import os
from types import SimpleNamespace

import pytest

from swapnet.adapters import coin_string
from swapnet.assets import Asset
from swapnet.authorization import Authority, Principal
from swapnet.canonical import atoms, digest
from swapnet.coordinator import Coordinator
from swapnet.drivers import UTXODriver
from swapnet.errors import SwapError
from swapnet.evm import keccak256, lock_id
from swapnet.evm_driver import EVMDriver
from swapnet.funding_scan import find_funding_output
from swapnet.journal import Journal, local_dump
from swapnet.policy import Mandate, SafetyPolicy
from swapnet.quote import Quote
from swapnet.store import Store
from swapnet.terms import Agreement
from swapnet.vault import ForeignKeyVault
from test_execution_v2 import A, NETWORK, Driver, Identity, Ledger, Time, pair

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
    # The execution double has no chain RPC. Family alone must not start a scan.
    driver.family = "evm"
    assert find_funding_output(driver, terms("cc"), "ab" * 32) is None
    driver.scan_existing_funding = lambda _terms: {"txid": TXID, "vout": 3}
    assert find_funding_output(driver, terms("cc")) == {"txid": TXID, "vout": 3}

    class Bare:
        family = "btc"

    with pytest.raises(SwapError, match="FUNDING_LOOKUP"):
        find_funding_output(Bare(), terms("cc"))


ETH_GENESIS = "12" * 32
ETH = Asset("evm", ETH_GENESIS, 1, "native")
ETH_CONTRACT = "0x" + "44" * 20
ETH_CODE = bytes(range(1, 33))
ETH_RUNTIME = keccak256(ETH_CODE).hex()
EVM_SID = "cd" * 32
FUNDING_TX = "ef" * 32


def encode_swap(hashlock, token, refund_to, claim_to, amount, refund_at, state):
    def word(raw):
        return raw.rjust(32, b"\x00")

    parts = [
        bytes.fromhex(hashlock),
        bytes.fromhex(token.removeprefix("0x")),
        bytes.fromhex(refund_to.removeprefix("0x")),
        bytes.fromhex(claim_to.removeprefix("0x")),
        amount.to_bytes(32, "big"),
        refund_at.to_bytes(32, "big"),
        state.to_bytes(32, "big"),
    ]
    return "0x" + b"".join(word(part) for part in parts).hex()


def evm_terms(asset=ETH.id, **overrides):
    body = {
        "asset": asset,
        "hashlock": "ab" * 32,
        "refund_key": "0x" + "22" * 20,
        "claim_key": "0x" + "33" * 20,
        "amount_atoms": "10000",
        "lock_value": 1_900_000_000,
    }
    body.update(overrides)
    return SimpleNamespace(**body)


class ScriptedEVM:
    family = "evm"

    def __init__(self, view, logs=None, fail=None):
        self.asset = ETH
        self.contract = ETH_CONTRACT
        self.view = view
        self.logs = [] if logs is None else logs
        self.fail = fail or set()
        self.calls = []

    def rpc(self, method, *args):
        self.calls.append((method, args))
        if method in self.fail:
            raise RuntimeError("down")
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_call":
            return self.view
        if method == "eth_getLogs":
            return self.logs
        raise AssertionError(method)


def locked_log(terms, lock, txid):
    topic = "0x" + keccak256(b"Locked(bytes32,bytes32,address,address,address,uint256,uint64)").hex()
    return {
        "address": ETH_CONTRACT,
        "topics": [
            topic,
            "0x" + lock,
            "0x" + terms.refund_key[2:].rjust(64, "0"),
            "0x" + terms.claim_key[2:].rjust(64, "0"),
        ],
        "transactionHash": "0x" + txid,
        "removed": False,
    }


def expected_lock(terms, txid="00" * 32):
    salt = digest("BTX/SWAPNET/EVM-SALT/2", {"swap_id": EVM_SID, "asset": terms.asset})
    return {
        "txid": "0x" + txid,
        "lock_id": lock_id(ETH.chain_id, ETH_CONTRACT, terms.refund_key, salt),
        "salt": salt,
    }


def test_evm_storage_lock_is_adopted_with_its_funding_transaction():
    leg = evm_terms()
    expected = expected_lock(leg, FUNDING_TX)
    view = encode_swap(leg.hashlock, "0x" + "00" * 20, leg.refund_key, leg.claim_key, 10000, leg.lock_value, 1)
    driver = ScriptedEVM(view, [locked_log(leg, expected["lock_id"], FUNDING_TX)])
    found = find_funding_output(driver, leg, EVM_SID)
    assert found == expected
    call = next(args for method, args in driver.calls if method == "eth_call")
    assert call[0]["to"] == ETH_CONTRACT
    assert bytes.fromhex(call[0]["data"][2:])[4:] == bytes.fromhex(expected["lock_id"])
    # Claimed storage still occupies the id. A second lockNative would revert.
    driver.view = encode_swap(leg.hashlock, "0x" + "00" * 20, leg.refund_key, leg.claim_key, 10000, leg.lock_value, 2)
    assert find_funding_output(driver, leg, EVM_SID)["lock_id"] == expected["lock_id"]


def test_evm_absent_lock_returns_none_without_reading_logs():
    leg = evm_terms()
    view = encode_swap(leg.hashlock, "0x" + "00" * 20, leg.refund_key, leg.claim_key, 0, 0, 0)
    driver = ScriptedEVM(view, [{"transactionHash": "0x" + FUNDING_TX}])
    assert find_funding_output(driver, leg, EVM_SID) is None
    assert "eth_getLogs" not in [method for method, _args in driver.calls]


def test_evm_lock_without_a_log_keeps_the_lock_id():
    leg = evm_terms()
    view = encode_swap(leg.hashlock, "0x" + "00" * 20, leg.refund_key, leg.claim_key, 10000, leg.lock_value, 1)
    driver = ScriptedEVM(view, [])
    assert find_funding_output(driver, leg, EVM_SID) == expected_lock(leg)


def test_evm_lookup_problems_do_not_return_a_funding_reference():
    leg = evm_terms()
    present = encode_swap(leg.hashlock, "0x" + "00" * 20, leg.refund_key, leg.claim_key, 10000, leg.lock_value, 1)
    expected = expected_lock(leg, FUNDING_TX)
    mismatch = encode_swap(leg.hashlock, "0x" + "00" * 20, leg.refund_key, leg.claim_key, 10001, leg.lock_value, 1)
    with pytest.raises(SwapError, match="FUNDING_LOOKUP"):
        find_funding_output(ScriptedEVM(mismatch, [locked_log(leg, expected["lock_id"], FUNDING_TX)]), leg, EVM_SID)
    with pytest.raises(SwapError, match="FUNDING_LOOKUP"):
        find_funding_output(ScriptedEVM(present, fail={"eth_call"}), leg, EVM_SID)
    ambiguous = [
        locked_log(leg, expected["lock_id"], FUNDING_TX),
        locked_log(leg, expected["lock_id"], "12" * 32),
    ]
    with pytest.raises(SwapError, match="FUNDING_LOOKUP"):
        find_funding_output(ScriptedEVM(present, ambiguous), leg, EVM_SID)


class AdoptingEVM(EVMDriver):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.funding_calls = 0

    def prepare_funding(self, *args, **kwargs):
        self.funding_calls += 1
        raise AssertionError("prepare_funding")


class EthChain:
    def __init__(self, now):
        self.now = now
        self.fail = set()
        self.view = "0x" + "00" * 224
        self.logs = []

    def rpc(self, method, *args):
        if method in self.fail:
            raise SwapError("CHAIN_RPC", "lookup failed")
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_syncing":
            return False
        if method == "eth_getCode":
            return "0x" + ETH_CODE.hex()
        if method == "eth_getBlockByNumber":
            if args[0] == "0x0":
                return {"hash": "0x" + ETH_GENESIS, "number": "0x0", "timestamp": "0x0"}
            return {"hash": "0x" + "ab" * 32, "number": "0x64", "timestamp": hex(self.now()), "baseFeePerGas": "0x1"}
        if method == "eth_call":
            return self.view
        if method == "eth_getLogs":
            return self.logs
        if method == "eth_getTransactionReceipt":
            return None
        raise SwapError("CHAIN_RPC", method)


class EthPair:
    """Initiator sells ETH and buys BTX, stopped at the committed restore point."""

    def __init__(self, path):
        self.path = path
        self.time = Time()
        self.btx = Ledger(A, self.time)
        self.chain = EthChain(self.time)
        self.queue = []
        self.nodes = {}
        self.identities = {name: Identity(name) for name in ("alice", "bob")}
        for name in self.identities:
            self.open(name)

    def open(self, name):
        folder = self.path / name
        folder.mkdir(mode=0o700, exist_ok=True)
        store = Store(folder / "state.db")
        journal = Journal(store)
        authority = Authority(store, journal, self.time)
        vault = ForeignKeyVault(folder / "vault.json", b"0123456789abcdef0123456789abcdef")
        evm = AdoptingEVM(ETH.id, self.chain.rpc, journal, vault, ETH_CONTRACT, ETH_RUNTIME, clock=self.time)
        coordinator = Coordinator(
            journal, authority, {ETH.id: evm, A: Driver(self.btx, name)}, self.identities[name], vault,
            lambda peer, kind, sid, body: self.queue.append((name, peer, kind, sid, body)),
            clock=self.time,
            policy=SafetyPolicy(btx_confirmations=2, btc_confirmations=2, settlement_margin_seconds=10, reveal_margin_seconds=10),
        )
        self.nodes[name] = (store, journal, authority, coordinator)

    def close(self):
        for name in self.nodes:
            self.nodes[name][0].close()

    def mandate(self, name, asset):
        mandate = Mandate(name, asset, "10000000", "100000", "1000", self.time() + 100000, "33" * 32)
        return self.nodes[name][2].install(Principal(name, True), asdict(mandate))

    def start(self):
        alice_mandate = self.mandate("alice", ETH.id)
        bob_mandate = self.mandate("bob", A)
        requester = digest("BTX/SWAPNET/REQUESTER/2", {"identity": "alice", "nonce": "44" * 32})
        rfq = {
            "network": NETWORK, "requester": requester, "sell_asset": ETH.id, "buy_asset": A,
            "sell_atoms": "10000", "nonce": "44" * 32, "issued_at": self.time(), "expires_at": self.time() + 120,
        }
        quote = Quote(NETWORK, "bob", requester, "55" * 32, 1, ETH.id, A, "10000", "20000", "10", "100", self.time(), self.time() + 120)
        envelope = {"quote": asdict(quote), "signature": self.identities["bob"].sign(quote.signing_message)}
        self.market = {
            "principal": "bob", "wallet": "", "mandate_id": bob_mandate, "max_local_fee_atoms": "500",
            "refund_fee_atoms": "100", "claim_fee_atoms": "100",
            "market": {
                "sell_asset": ETH.id, "buy_asset": A, "numerator": "2", "denominator": "1", "maker_fee_atoms": "10",
                "max_receive_network_fee_atoms": "100", "max_input_atoms": "100000", "expires_at": self.time() + 10000,
            },
        }
        self.sid = self.nodes["alice"][3].start(Principal("alice"), envelope, rfq, alice_mandate, "500", "100")["swap_id"]
        return self.sid

    def deliver(self):
        count = 0
        while self.queue:
            sender, peer, kind, sid, body = self.queue.pop(0)
            coordinator = self.nodes[peer][3]
            if kind == "proposal":
                coordinator.receive_proposal(sender, sid, body, self.market)
            elif kind == "agreement":
                coordinator.receive_agreement(sender, sid, body)
            elif kind == "commit":
                coordinator.receive_commit(sender, sid, body)
            elif kind == "funded":
                coordinator.receive_reference(sender, sid, body)
            elif kind == "cancel":
                coordinator.receive_cancel(sender, sid, body)
            count += 1
            assert count < 100

    def state(self, name):
        return self.nodes[name][1].load(self.sid)[1]


def plant_eth_lock(pair):
    terms = Agreement.parse(pair.state("alice")["agreement"]).long_leg
    driver = pair.nodes["alice"][3].drivers[ETH.id]
    ref = driver.reference(pair.sid, terms, "0x" + FUNDING_TX)
    pair.chain.view = encode_swap(
        terms.hashlock, "0x" + "00" * 20, terms.refund_key, terms.claim_key,
        int(terms.amount_atoms), terms.lock_value, 1,
    )
    pair.chain.logs = [locked_log(terms, ref["lock_id"], FUNDING_TX)]
    return ref


@pytest.fixture
def eth_pair(tmp_path):
    pair = EthPair(tmp_path)
    try:
        pair.start()
        pair.deliver()
        assert pair.state("alice")["stage"] == "committed"
        assert not pair.state("alice")["funding_prepared"]
        yield pair
    finally:
        pair.close()


def test_existing_evm_lock_is_adopted_and_prepare_funding_is_not_called(eth_pair):
    ref = plant_eth_lock(eth_pair)
    alice = eth_pair.nodes["alice"][3]
    driver = alice.drivers[ETH.id]
    alice.tick_one(eth_pair.sid)
    alice.tick_one(eth_pair.sid)
    assert driver.funding_calls == 0
    state = eth_pair.state("alice")
    assert state["refs"]["a"] == ref
    assert state["funding_broadcast"] is True and state["recovery_ready"] is True
    assert state["stage"] == "funded"
    assert state["evm_refund_plan"]["lock_id"] == ref["lock_id"]
    ops = eth_pair.nodes["alice"][1].operations(eth_pair.sid, private=True)
    assert [op["kind"] for op in ops] == []


def test_evm_lookup_failure_does_not_fund(eth_pair):
    driver = eth_pair.nodes["alice"][3].drivers[ETH.id]
    eth_pair.chain.fail.add("eth_call")
    with pytest.raises(SwapError, match="FUNDING_LOOKUP"):
        eth_pair.nodes["alice"][3].tick_one(eth_pair.sid)
    assert driver.funding_calls == 0
    state = eth_pair.state("alice")
    assert state["stage"] == "committed" and not state["funding_prepared"]
    assert eth_pair.nodes["alice"][1].operations(eth_pair.sid) == []


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
