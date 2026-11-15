#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""-walletdepositnotify reports utxo.spent for a deposit the wallet spends.

doc/integrations/bcp1.md lists utxo.spent ("Output consumed") among the BCP/1
events, and getdepositstatus turns SPENT as soon as a wallet transaction
spends the output. The deposit notify command runs for the transaction the
wallet adds, which is the spender, so the spent deposit has to be reported
from there, with %s and the JSON txid/vout naming the deposit and spent_by
naming the spender. A replacement spender reports the deposit spent again,
naming the replacement. A deposit spent before it confirms is reported once,
when it confirms.
"""
import json
import os
import time
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBCP1DepositNotifySpentTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.events_file = os.path.join(self.options.tmpdir, "deposit-events.txt")
        notify = f"echo %w %s %j >> {self.events_file}"
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + [
            "-autoshieldcoinbase=0", "-nomodelnet", f"-walletdepositnotify={notify}"]]
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def events(self, event):
        """(%s, JSON) of the venue wallet's events named event, in the order they were written."""
        out = []
        if not os.path.exists(self.events_file):
            return out
        with open(self.events_file, encoding="utf8") as f:
            for line in f:
                wallet, txid, payload = line.rstrip("\n").split(" ", 2)
                data = json.loads(payload)
                if wallet == "venue" and data["event"] == event:
                    out.append((txid, data))
        return out

    def settle(self):
        """Wait until the notify commands, which run on their own threads, stop writing."""
        self.nodes[0].syncwithvalidationinterfacequeue()
        last = -1
        for _ in range(50):
            size = os.path.getsize(self.events_file) if os.path.exists(self.events_file) else 0
            if size == last:
                return
            last = size
            time.sleep(0.4)

    def spent(self, txid, vout):
        """spent_by of each utxo.spent event for one deposit output, in order."""
        self.settle()
        return [e["spent_by"] for _, e in self.events("utxo.spent") if e["txid"] == txid and e["vout"] == vout]

    def wait_for(self, event, txid):
        self.nodes[0].syncwithvalidationinterfacequeue()
        self.wait_until(lambda: any(e["txid"] == txid for _, e in self.events(event)), timeout=30)

    def deposit(self, amount):
        txid = self.miner.sendtoaddress(self.venue.getnewaddress(), amount)
        self.wait_for("deposit.detected", txid)
        vout = [u["vout"] for u in self.venue.listunspent(0) if u["txid"] == txid][0]
        return txid, vout

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        self.miner = node.get_wallet_rpc("miner")
        node.createwallet("venue")
        self.venue = node.get_wallet_rpc("venue")
        self.generatetoaddress(node, 110, self.miner.getnewaddress(), sync_fun=self.no_op)

        self.log.info("Spending a whole deposit reports it as spent")
        first, first_vout = self.deposit(Decimal("4"))
        self.generatetoaddress(node, 1, self.miner.getnewaddress(), sync_fun=self.no_op)
        sweep = self.venue.sendall([self.miner.getnewaddress()])["txid"]
        self.wait_for("utxo.spent", first)
        assert_equal(self.venue.getdepositstatus(first, first_vout)["status"], "SPENT")
        [(notified, event)] = [(s, e) for s, e in self.events("utxo.spent") if e["txid"] == first]
        assert_equal(notified, first)
        assert_equal(event["vout"], first_vout)
        assert_equal(event["status"], "SPENT")
        assert_equal(event["spent_by"], sweep)

        self.log.info("Spending part of a deposit reports it as spent, and the change as a new output")
        second, second_vout = self.deposit(Decimal("3"))
        self.generatetoaddress(node, 1, self.miner.getnewaddress(), sync_fun=self.no_op)
        payout = self.venue.sendtoaddress(self.miner.getnewaddress(), Decimal("1"))
        self.wait_for("utxo.spent", second)
        self.wait_for("utxo.created", payout)
        [(_, event)] = [(s, e) for s, e in self.events("utxo.spent") if e["txid"] == second]
        assert_equal(event["vout"], second_vout)
        assert_equal(event["spent_by"], payout)

        self.log.info("A confirmation does not report the spend again, and an unspent deposit is not reported")
        unspent, unspent_vout = self.deposit(Decimal("2"))
        self.generatetoaddress(node, 1, self.miner.getnewaddress(), sync_fun=self.no_op)
        assert_equal(self.spent(first, first_vout), [sweep])
        assert_equal(self.spent(second, second_vout), [payout])
        assert_equal(self.spent(unspent, unspent_vout), [])

        self.log.info("A replaced spender reports the deposit spent again, by the replacement")
        payout_options = {"inputs": [{"txid": unspent, "vout": unspent_vout}], "add_inputs": False, "replaceable": True}
        original = self.venue.send(outputs=[{self.miner.getnewaddress(): Decimal("1")}], options=payout_options)["txid"]
        self.wait_for("utxo.spent", unspent)
        bumped = self.venue.bumpfee(original)["txid"]
        self.generatetoaddress(node, 1, self.miner.getnewaddress(), sync_fun=self.no_op)
        assert_equal(self.spent(unspent, unspent_vout), [original, bumped])

        self.log.info("A deposit spent before it confirms is reported once, when it confirms")
        chained = self.venue.send(outputs=[{self.venue.getnewaddress(): Decimal("1")}])["txid"]
        chained_vout = [u["vout"] for u in self.venue.listunspent(0) if u["txid"] == chained and u["amount"] == Decimal("1")][0]
        spender = self.venue.send(outputs=[{self.miner.getnewaddress(): Decimal("0.5")}],
                                  options={"inputs": [{"txid": chained, "vout": chained_vout}], "add_inputs": False})["txid"]
        self.wait_for("utxo.created", spender)
        assert_equal(self.spent(chained, chained_vout), [])
        self.generatetoaddress(node, 1, self.miner.getnewaddress(), sync_fun=self.no_op)
        assert_equal(self.spent(chained, chained_vout), [spender])


if __name__ == '__main__':
    WalletBCP1DepositNotifySpentTest(__file__).main()
