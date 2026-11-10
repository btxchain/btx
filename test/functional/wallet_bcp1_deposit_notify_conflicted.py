#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""-walletdepositnotify reports a deposit that a conflicting transaction replaced.

getdepositstatus reports CONFLICTED when another transaction spending the same
prevout is in the active chain or mempool. The wallet marks that conflict
without going through AddToWallet, so the deposit notify command has to run
from the conflict path as well, with the event transaction.conflicted:

- a sender fee-bumps a pending deposit: the replaced txid is CONFLICTED;
- a confirmed deposit is reorged out and a double-spend wins: the deposit
  goes from REORGED to CONFLICTED.

Each happens once per deposit, and the replacement that pays the deposit
address is not reported as conflicted.
"""
import os
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBCP1DepositNotifyConflictedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.events_file = os.path.join(self.options.tmpdir, "deposit-events.txt")
        notify = f"echo %w %e %s >> {self.events_file}"
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + [
            "-autoshieldcoinbase=0", "-nomodelnet", f"-walletdepositnotify={notify}"]]
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def events(self, txid):
        """Deposit events of the venue wallet for txid, in the order they were written."""
        if not os.path.exists(self.events_file):
            return []
        with open(self.events_file, encoding="utf8") as f:
            return [line.split()[1] for line in f if line.startswith("venue ") and txid in line]

    def wait_for_event(self, txid, event):
        self.nodes[0].syncwithvalidationinterfacequeue()
        self.wait_until(lambda: event in self.events(txid), timeout=30)

    def status(self, txid, address):
        decoded = self.venue.gettransaction(txid, True, True)["decoded"]
        vout = [o["n"] for o in decoded["vout"] if o["scriptPubKey"].get("address") == address][0]
        return self.venue.getdepositstatus(txid, vout)["status"]

    def pool_address(self):
        pubkey = self.source.getaddressinfo(self.source.getnewaddress())["pubkey"]
        return pubkey, self.nodes[0].deriveaddresses(f"mr({pubkey})", None, {"require_checksum": False})[0]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        miner = node.get_wallet_rpc("miner")
        node.createwallet("source")
        self.source = node.get_wallet_rpc("source")
        node.createwallet("sender")
        sender = node.get_wallet_rpc("sender")
        self.generatetoaddress(node, 110, miner.getnewaddress(), sync_fun=self.no_op)
        for _ in range(3):
            miner.sendtoaddress(sender.getnewaddress(), Decimal("10"))
        self.generatetoaddress(node, 1, miner.getnewaddress(), sync_fun=self.no_op)

        node.createwallet(wallet_name="venue", disable_private_keys=True, blank=True)
        self.venue = node.get_wallet_rpc("venue")
        pubkeys = []
        addresses = []
        for _ in range(3):
            pubkey, address = self.pool_address()
            pubkeys.append(pubkey)
            addresses.append(address)
        self.venue.importdepositpool([{"pubkey": pk, "index": i} for i, pk in enumerate(pubkeys)])

        self.log.info("A fee bump reports the replaced deposit as conflicted")
        replaced = sender.send(outputs=[{addresses[0]: Decimal("2")}], options={"replaceable": True})["txid"]
        self.wait_for_event(replaced, "transaction.mempool")
        replacement = sender.bumpfee(replaced)["txid"]
        self.wait_for_event(replacement, "transaction.mempool")
        self.wait_for_event(replaced, "transaction.conflicted")
        assert_equal(self.status(replaced, addresses[0]), "CONFLICTED")
        assert_equal(self.status(replacement, addresses[0]), "MEMPOOL")
        self.generatetoaddress(node, 1, miner.getnewaddress(), sync_fun=self.no_op)
        assert_equal(self.status(replaced, addresses[0]), "CONFLICTED")

        self.log.info("A reorged deposit that loses to a double-spend is reported as conflicted")
        deposit = sender.send(outputs=[{addresses[1]: Decimal("3")}], options={"replaceable": True})["txid"]
        self.wait_for_event(deposit, "transaction.mempool")
        block = self.generatetoaddress(node, 1, miner.getnewaddress(), sync_fun=self.no_op)[0]
        assert_equal(self.status(deposit, addresses[1]), "CONFIRMED")
        node.invalidateblock(block)
        self.wait_for_event(deposit, "transaction.reorged")
        assert_equal(self.status(deposit, addresses[1]), "REORGED")
        inputs = [{"txid": i["txid"], "vout": i["vout"]} for i in node.getrawtransaction(deposit, True)["vin"]]
        spent = sum(Decimal(str(sender.gettransaction(i["txid"], True, True)["decoded"]["vout"][i["vout"]]["value"]))
                    for i in inputs)
        double_spend = sender.signrawtransactionwithwallet(
            sender.createrawtransaction(inputs, [{sender.getnewaddress(): spent - Decimal("0.05")}]))["hex"]
        node.sendrawtransaction(double_spend)
        self.wait_for_event(deposit, "transaction.conflicted")
        assert_equal(self.status(deposit, addresses[1]), "CONFLICTED")
        self.generatetoaddress(node, 2, miner.getnewaddress(), sync_fun=self.no_op)
        assert_equal(self.status(deposit, addresses[1]), "CONFLICTED")

        self.log.info("Each conflict is reported once, and only for the deposit that lost")
        # A later deposit's events are written after anything the steps above queued.
        marker = sender.send(outputs=[{addresses[2]: Decimal("1")}])["txid"]
        self.wait_for_event(marker, "transaction.mempool")
        assert_equal(self.events(replaced).count("transaction.conflicted"), 1)
        assert_equal(self.events(deposit).count("transaction.conflicted"), 1)
        assert "transaction.conflicted" not in self.events(replacement)
        assert "transaction.conflicted" not in self.events(marker)


if __name__ == '__main__':
    WalletBCP1DepositNotifyConflictedTest(__file__).main()
