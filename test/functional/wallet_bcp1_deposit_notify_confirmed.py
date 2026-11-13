#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""-walletdepositnotify reports the confirmation of a deposit first seen in the mempool.

A deposit to a watch-only pool reaches the mempool first: deposit.detected,
utxo.created and transaction.mempool. When a block includes it, the venue must
get transaction.confirmed (doc/integrations/bcp1.md) and
deposit.confirmations_changed. After the confirming block is disconnected and
connected again, transaction.confirmed must come again, for every pool output
of the transaction. A payment the wallet
makes itself is known to the wallet before it reaches the mempool; its change
must still be reported when it does, and confirmed with the block.
"""
import os
import time
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBCP1DepositNotifyConfirmedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # node0 holds the venue's watch-only pool and, later, one wallet that pays out;
        # events are told apart by txid.
        self.events_file = os.path.join(self.options.tmpdir, "deposit-events.txt")
        # -dandelion=0: a stem transaction can wait for the next Dandelion++ epoch
        # before it reaches the other node, which would stall sync_mempools.
        base = list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet", "-dandelion=0"]
        self.extra_args = [base + [f"-walletdepositnotify=echo %e %s >> {self.events_file}"], base]
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def read_events(self, txid):
        if not os.path.exists(self.events_file):
            return []
        with open(self.events_file) as f:
            return [line.split()[0] for line in f if txid in line]

    def events(self, txid, until=lambda names: True):
        """Event names for txid. The notify commands run on their own threads, so wait
        (up to 30 s) until `until` holds, then until they stop writing."""
        self.nodes[0].syncwithvalidationinterfacequeue()
        deadline = time.time() + 30
        names = self.read_events(txid)
        while not until(names) and time.time() < deadline:
            time.sleep(0.2)
            names = self.read_events(txid)
        for _ in range(50):
            time.sleep(0.2)
            later = self.read_events(txid)
            if later == names:
                break
            names = later
        return names

    def run_test(self):
        venue_node, funder_node = self.nodes
        funder_node.createwallet("miner")
        miner = funder_node.get_wallet_rpc("miner")
        funder_node.createwallet("source")
        source = funder_node.get_wallet_rpc("source")
        self.generatetoaddress(funder_node, 110, miner.getnewaddress())

        pubkey = source.getaddressinfo(source.getnewaddress())["pubkey"]
        address = venue_node.deriveaddresses(f"mr({pubkey})", None, {"require_checksum": False})[0]
        venue_node.createwallet(wallet_name="venue", disable_private_keys=True, blank=True)
        venue = venue_node.get_wallet_rpc("venue")
        assert_equal(venue.importdepositpool([{"pubkey": pubkey, "index": 0}])["success"], True)

        self.log.info("A deposit in the mempool")
        txid = miner.sendtoaddress(address, Decimal("3"))
        self.sync_mempools()
        seen = self.events(txid, lambda n: len(n) >= 3)
        assert_equal(sorted(seen), sorted(["deposit.detected", "utxo.created", "transaction.mempool"]))

        self.log.info("The block that includes it confirms it")
        block = self.generatetoaddress(funder_node, 1, miner.getnewaddress())[0]
        confirmed = self.events(txid, lambda n: {"transaction.confirmed", "deposit.confirmations_changed"} <= set(n[len(seen):]))[len(seen):]
        self.log.info(f"Events for the block: {confirmed}")
        assert "transaction.confirmed" in confirmed, f"no transaction.confirmed after the block: {confirmed}"
        assert "deposit.confirmations_changed" in confirmed, confirmed
        assert "deposit.detected" not in confirmed, confirmed

        self.log.info("Disconnected and connected again, it is confirmed again")
        before = len(self.events(txid))
        venue_node.invalidateblock(block)
        venue_node.reconsiderblock(block)
        again = self.events(txid, lambda n: {"transaction.reorged", "transaction.confirmed"} <= set(n[before:]))[before:]
        self.log.info(f"Events for the disconnect and reconnect: {again}")
        assert "transaction.reorged" in again, again
        assert "transaction.confirmed" in again, f"no transaction.confirmed after the block came back: {again}"

        self.log.info("A deposit that pays two pool addresses confirms both outputs, also after a reorg")
        more = []
        for index in (1, 2):
            more_pubkey = source.getaddressinfo(source.getnewaddress())["pubkey"]
            more.append((index, more_pubkey,
                         venue_node.deriveaddresses(f"mr({more_pubkey})", None, {"require_checksum": False})[0]))
        venue.importdepositpool([{"pubkey": pk, "index": i} for i, pk, _ in more])
        both = miner.sendmany("", {addr: Decimal("1") for _, _, addr in more})
        self.sync_mempools()
        pending = self.events(both, lambda n: n.count("transaction.mempool") >= 2)
        assert_equal(pending.count("transaction.mempool"), 2)
        both_block = self.generatetoaddress(funder_node, 1, miner.getnewaddress())[0]
        confirmed_both = self.events(both, lambda n: n[len(pending):].count("transaction.confirmed") >= 2)[len(pending):]
        assert_equal(confirmed_both.count("transaction.confirmed"), 2)
        before = len(self.events(both))
        venue_node.invalidateblock(both_block)
        venue_node.reconsiderblock(both_block)
        assert_equal(self.events(both, lambda n: n[before:].count("transaction.confirmed") >= 2)[before:].count("transaction.confirmed"), 2)

        self.log.info("The change of a payment the node's own wallet makes is reported, then confirmed")
        venue_node.createwallet("hot")
        hot = venue_node.get_wallet_rpc("hot")
        miner.sendtoaddress(hot.getnewaddress(), Decimal("5"))
        self.generatetoaddress(funder_node, 1, miner.getnewaddress())
        payment = hot.sendtoaddress(miner.getnewaddress(), Decimal("1"))
        self.sync_mempools()
        sent = self.events(payment, lambda n: len(n) >= 3)
        assert_equal(sorted(sent), sorted(["deposit.detected", "utxo.created", "transaction.mempool"]))
        self.generatetoaddress(funder_node, 1, miner.getnewaddress())
        paid = self.events(payment, lambda n: "transaction.confirmed" in n[len(sent):])[len(sent):]
        assert "transaction.confirmed" in paid, f"no transaction.confirmed for the payment's change: {paid}"

        self.log.info("A deposit spent before it confirms is still reported confirmed")
        received = miner.sendtoaddress(hot.getnewaddress(), Decimal("2"))
        self.sync_mempools()
        pending = self.events(received, lambda n: len(n) >= 3)
        assert_equal(sorted(pending), sorted(["deposit.detected", "utxo.created", "transaction.mempool"]))
        vout = [u["vout"] for u in hot.listunspent(0) if u["txid"] == received][0]
        spend = hot.send(outputs=[{miner.getnewaddress(): Decimal("1")}],
                         options={"inputs": [{"txid": received, "vout": vout}], "add_inputs": False, "include_unsafe": True})
        assert spend["complete"], spend
        self.sync_mempools()
        self.generatetoaddress(funder_node, 1, miner.getnewaddress())
        mined = self.events(received, lambda n: "transaction.confirmed" in n[len(pending):])[len(pending):]
        self.log.info(f"Events for the block: {mined}")
        assert "transaction.confirmed" in mined, f"no transaction.confirmed for a deposit spent before it confirmed: {mined}"


if __name__ == "__main__":
    WalletBCP1DepositNotifyConfirmedTest(__file__).main()
