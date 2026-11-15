import copy
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "watchtower.py"
spec = importlib.util.spec_from_file_location("native_watchtower", MODULE)
watchtower = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchtower)

FUNDING = "11" * 32
REFUND = "22" * 32
TIP = "33" * 32
TERMS = {
    "key_hash": "44" * 32, "claimant": "55" * 1312, "refund_pubkey": "66" * 1312,
    "refund_height": 120, "amount_atoms": "10000000",
}


class Node:
    def __init__(self):
        self.chain = "regtest"
        self.height = 110
        self.tip = TIP
        self.owned = True
        self.utxo = True
        self.confirmed = False
        self.mempool = []
        self.allowed = True
        self.sent = 0
        self.fail_after_send = False
        self.decoded = {
            "txid": REFUND, "locktime": 120,
            "vin": [{"txid": FUNDING, "vout": 0, "sequence": 0xfffffffe, "txinwitness": ["11", "22", "33"]}],
            "vout": [{"value": "0.0999", "scriptPubKey": {"hex": "5120" + "99" * 32}}],
        }

    def call(self, method, *params):
        if method == "getblockchaininfo":
            return {"chain": self.chain, "blocks": self.height, "headers": self.height, "bestblockhash": self.tip, "initialblockdownload": False}
        if method == "getaddressinfo":
            return {"ismine": self.owned, "scriptPubKey": "5120" + "99" * 32}
        if method == "getmodelfundingsettlement":
            if len(params) == 3:
                if not self.confirmed and REFUND not in self.mempool:
                    raise watchtower.PaymentError("unknown")
                return {"settled": self.confirmed, "branch": "REFUND", "settlement_txid": REFUND, "chain_tip": self.tip}
            return {"funded": True, "state": "FUNDED" if self.utxo else "SPENT_UNRESOLVED", "funding_vout": 0, "chain_tip": self.tip, "refund_leaf": "22"}
        if method == "decoderawtransaction":
            return copy.deepcopy(self.decoded)
        if method == "gettxout":
            return {"value": "0.1"} if self.utxo else None
        if method == "getrawmempool":
            return list(self.mempool)
        if method == "testmempoolaccept":
            return [{"allowed": self.allowed, "reject-reason": "rejected-test"}]
        if method == "sendrawtransaction":
            self.sent += 1
            self.mempool = [REFUND]
            self.utxo = False
            if self.fail_after_send:
                self.fail_after_send = False
                raise watchtower.PaymentError("simulated crash after broadcast")
            return REFUND
        raise AssertionError(f"unexpected RPC {method}")


class WatchtowerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "recovery.db"
        self.node = Node()
        self.tower = watchtower.RefundWatchtower(self.path, self.node)

    def tearDown(self):
        self.tower.close()
        self.tmp.cleanup()

    def register(self, sequence=1):
        return self.tower.register(FUNDING, TERMS, "owner", "ab" * 100, "100000", sequence)

    def test_bounded_refund_waits_until_height_then_reconciles_confirmation(self):
        self.register()
        self.assertEqual(self.tower.poll()[0]["state"], "WAITING")
        self.assertEqual(self.node.sent, 0)
        self.node.height = 120
        self.assertEqual(self.tower.poll()[0]["state"], "SUBMITTED")
        self.assertEqual(self.node.sent, 1)
        self.assertEqual(self.tower.poll()[0]["state"], "SUBMITTED")
        self.assertEqual(self.node.sent, 1)
        self.node.confirmed = True
        self.node.mempool = []
        self.assertEqual(self.tower.poll()[0]["state"], "CONFIRMED")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_mainnet_and_wrong_owner_are_refused(self):
        self.node.chain = "main"
        with self.assertRaisesRegex(watchtower.PaymentError, "restricted"):
            self.register()
        self.node.chain = "regtest"
        self.node.owned = False
        with self.assertRaisesRegex(watchtower.PaymentError, "not owned"):
            self.register()
        self.assertEqual(self.tower.status(), [])

    def test_semantic_mutations_are_refused(self):
        for mutation in (
            lambda tx: tx["vin"][0].update(vout=1),
            lambda tx: tx["vin"][0].update(sequence=0xffffffff),
            lambda tx: tx.update(locktime=119),
            lambda tx: tx["vin"][0].update(txinwitness=["11", "wrong-leaf", "33"]),
            lambda tx: tx["vout"][0].update(value="0.01"),
            lambda tx: tx["vout"][0]["scriptPubKey"].update(hex="51"),
        ):
            before = copy.deepcopy(self.node.decoded)
            mutation(self.node.decoded)
            with self.assertRaises(watchtower.PaymentError):
                self.register()
            self.node.decoded = before
        self.assertEqual(self.tower.status(), [])

    def test_idempotent_register_and_stale_sequence(self):
        self.assertFalse(self.register()["duplicate"])
        self.assertTrue(self.register()["duplicate"])
        self.register(sequence=2)
        with self.assertRaisesRegex(watchtower.PaymentError, "stale"):
            self.register(sequence=1)
        self.assertEqual(self.tower.status()[0]["sequence"], 2)

    def test_reorg_revokes_confirmation(self):
        self.register()
        self.node.height = 120
        self.tower.poll()
        self.node.confirmed = True
        self.node.mempool = []
        self.assertEqual(self.tower.poll()[0]["state"], "CONFIRMED")
        self.node.confirmed = False
        self.node.utxo = True
        self.node.height = 119
        self.node.tip = "77" * 32
        self.assertEqual(self.tower.poll()[0]["state"], "WAITING")
        self.assertEqual(self.node.sent, 1)

    def test_crash_after_broadcast_is_idempotent_after_restart(self):
        self.register()
        self.node.height = 120
        self.node.fail_after_send = True
        with self.assertRaises(watchtower.PaymentError):
            self.tower.poll()
        self.tower.close()
        self.tower = watchtower.RefundWatchtower(self.path, self.node)
        self.assertEqual(self.tower.poll()[0]["state"], "SUBMITTED")
        self.assertEqual(self.node.sent, 1)

    def test_consensus_rejection_and_external_spend_never_trigger_send(self):
        self.register()
        self.node.height = 120
        self.node.allowed = False
        self.assertEqual(self.tower.poll()[0]["state"], "REJECTED")
        self.assertEqual(self.node.sent, 0)
        self.node.utxo = False
        self.assertEqual(self.tower.poll()[0]["state"], "SPENT_UNKNOWN")
        self.assertEqual(self.node.sent, 0)

    def test_amount_parser_never_rounds_or_accepts_bool(self):
        for bad in (True, False, 0.1, "01", "+1", "1.0", "1e3", "-1", " 1", str(watchtower.MAX_MONEY + 1)):
            with self.assertRaises(watchtower.PaymentError):
                watchtower.atoms(bad)
        self.assertEqual(watchtower.atoms("10000"), 10000)


if __name__ == "__main__":
    unittest.main()
