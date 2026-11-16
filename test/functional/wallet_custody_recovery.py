#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Recovery of retained watch-only inventory and unsigned input reservations.

The fixture consumer deliberately misses chain events and recovers through RPC.
It does not implement or certify a production exchange service.
"""
from decimal import Decimal
import json

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, find_vout_for_address


def selected(package):
    return {(row["txid"], row["vout"]) for row in package["selected_utxos"]}


def rpc_outpoints(outpoints):
    return [{"txid": txid, "vout": vout} for txid, vout in sorted(outpoints)]


class WalletCustodyRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0"]]

    def setup_network(self):
        if self.config["components"].getboolean("ENABLE_MODELNET", fallback=False):
            self.extra_args[0].append("-nomodelnet")
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def reservations(self, wallet):
        return {(row["txid"], row["vout"]) for row in wallet.listlockunspent()}

    def listener_recovery(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc("miner")
        source = node.get_wallet_rpc("source")
        node.createwallet("listener", disable_private_keys=True, blank=True)
        listener = node.get_wallet_rpc("listener")
        addresses = [source.getnewaddress() for _ in range(3)]
        listener.importdepositpool([{"address": a, "index": i + 30}
                                    for i, a in enumerate(addresses)])

        def deposit(address):
            coin = next(row for row in miner.listunspent(1) if row["amount"] > Decimal("2"))
            txid = miner.send(outputs=[{address: Decimal("2")}], options={
                "inputs": [{"txid": coin["txid"], "vout": coin["vout"]}],
                "add_inputs": False})["txid"]
            return txid, find_vout_for_address(node, txid, address)

        known = deposit(addresses[0])
        ancestor = self.generatetoaddress(node, 1, self.mining_address)[0]
        orphan = deposit(addresses[1])
        cursor = self.generatetoaddress(node, 1, self.mining_address)[0]
        credits = {known, orphan}
        cursor_file = node.datadir_path / "custody-consumer.json"
        cursor_file.write_text(json.dumps({"block": cursor, "credits": sorted(credits)}))
        assert_equal(listener.getdepositstatus(*orphan)["status"], "CONFIRMED")
        process = node.process
        pid = process.pid
        # The consumer now misses everything until reconciliation. The node stays up.
        node.invalidateblock(cursor)
        spender = source.send(outputs=[{self.mining_address: Decimal("1")}], options={
            "inputs": rpc_outpoints({known}), "add_inputs": False})["txid"]
        fresh = deposit(addresses[2])
        # Exclude the orphan payment, even though it may still be in the mempool.
        replacement = self.generateblock(node, self.mining_address,
                                         [spender, fresh[0]], sync_fun=self.no_op)["hash"]
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getblockheader(cursor)["confirmations"], -1)

        def reconcile(saved_hash, previous, attempts=3):
            tip = node.getbestblockhash()
            common = saved_hash
            while node.getblockheader(common)["confirmations"] == -1:
                common = node.getblockheader(common)["previousblockhash"]
            found = set(previous)
            first_height = node.getblockheader(common)["height"] + 1
            for height in range(first_height, node.getblockheader(tip)["height"] + 1):
                block = node.getblock(node.getblockhash(height), 2)
                for tx in block["tx"]:
                    for output in tx["vout"]:
                        if output["scriptPubKey"].get("address") in addresses:
                            found.add((tx["txid"], output["n"]))
            current = {outpoint for outpoint in found
                       if listener.getdepositstatus(*outpoint)["status"] == "CONFIRMED"}
            if node.getbestblockhash() != tip and attempts > 1:
                return reconcile(saved_hash, previous, attempts - 1)
            assert_equal(node.getbestblockhash(), tip)
            return common, tip, current

        retained = json.loads(cursor_file.read_text())
        common, tip, recovered = reconcile(retained["block"],
                                           {tuple(row) for row in retained["credits"]})
        assert_equal(common, ancestor)
        assert_equal(tip, replacement)
        assert_equal(recovered, {fresh})
        assert_equal(listener.getdepositstatus(*known)["status"], "SPENT")
        assert_equal(listener.getdepositstatus(*orphan)["status"], "REORGED")
        status = listener.getdepositstatus(*fresh)
        assert_equal(status["block_hash"], replacement)
        assert_equal(status["amount_atoms"], 200000000)
        assert_equal(status["confirmations"], 1)
        assert_equal(reconcile(tip, recovered)[2], recovered)
        rows = listener.listdepositutxos()
        assert_equal({(r["txid"], r["vout"]): r["status"] for r in rows},
                     {orphan: "REORGED", fresh: "CONFIRMED"})
        assert_equal(len(rows), 2)
        confirmed = listener.listdepositutxos({"minconf": 1})
        assert_equal([(r["txid"], r["vout"]) for r in confirmed], [fresh])
        assert_equal(node.process, process)
        assert_equal(node.process.pid, pid)
        assert_equal(process.poll(), None)
        assert_equal(listener.getwalletinfo()["private_keys_enabled"], False)

    def inventory_recovery(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc("miner")
        source = node.get_wallet_rpc("source")
        node.createwallet("inventory", disable_private_keys=True, blank=True)
        inventory = node.get_wallet_rpc("inventory")
        addresses = [source.getnewaddress() for _ in range(3)]
        entries = [{"address": address, "index": index + 10}
                   for index, address in enumerate(addresses)]
        inventory.importdepositpool(entries[:1])
        backup = node.datadir_path / "custody-inventory.bak"
        inventory.backupwallet(backup)
        inventory.importdepositpool(entries[1:])
        receipts = set()
        by_address = {}
        for address in addresses:
            txid = miner.sendtoaddress(address, Decimal("2"))
            outpoint = (txid, find_vout_for_address(node, txid, address))
            receipts.add(outpoint)
            by_address[address] = outpoint
        deposit_block = self.generatetoaddress(node, 1, self.mining_address)[0]
        deposit_height = node.getblockheader(deposit_block)["height"]
        spent = by_address[addresses[1]]
        source.send(outputs=[{self.mining_address: Decimal("1")}], options={
            "inputs": rpc_outpoints({spent}), "add_inputs": False})
        self.generatetoaddress(node, 1, self.mining_address)
        node.restorewallet("restored_inventory", backup)
        restored = node.get_wallet_rpc("restored_inventory")
        assert_equal(restored.getwalletinfo()["private_keys_enabled"], False)
        assert_raises_rpc_error(-4, "No imported pool entry for that index",
                                restored.deriveexchangeaddress, 11)
        restored.importdepositpool(entries, {"rescan": True})
        for index, address in enumerate(addresses):
            assert_equal(restored.deriveexchangeaddress(index + 10)["address"], address)

        def check():
            for index, address in enumerate(addresses):
                assert_equal(restored.deriveexchangeaddress(index + 10)["address"], address)
            for include_spent in (False, True):
                rows = restored.listdepositutxos({"include_spent": include_spent})
                actual = {(row["txid"], row["vout"]) for row in rows}
                assert_equal(len(actual), len(rows))
                assert_equal(actual, receipts if include_spent else receipts - {spent})
                for row in rows:
                    assert_equal(row["amount_atoms"], 200000000)
                    assert_equal(row["block_hash"], deposit_block)
                    assert_equal(row["block_height"], deposit_height)
                    assert_equal(row["confirmations"], node.getblockcount() - deposit_height + 1)
                    assert_equal(row["status"], "SPENT" if (row["txid"], row["vout"]) == spent else "CONFIRMED")
            assert_equal(restored.getwalletinfo()["private_keys_enabled"], False)

        check()
        restored.importdepositpool(entries, {"rescan": True})
        check()
        node.unloadwallet("restored_inventory")
        node.loadwallet("restored_inventory")
        restored = node.get_wallet_rpc("restored_inventory")
        check()

    def pending_recovery(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc("miner")
        venue = node.get_wallet_rpc("venue")
        addresses = self.addresses
        # Three eligible outputs cover pending A, unrelated B and a fresh disjoint C.
        funded = set()
        for address in addresses[:3]:
            txid = miner.sendtoaddress(address, Decimal("3"))
            funded.add((txid, find_vout_for_address(node, txid, address)))
        self.generatetoaddress(node, 1, self.mining_address)
        pay = [{"address": self.mining_address, "amount": Decimal("2")}]
        options = {"change_address": addresses[3], "lock_unspents": True}
        package = venue.createexchangebatch(pay, options)
        pending = selected(package)
        package_file = node.datadir_path / "custody-pending.json"
        package_file.write_text(json.dumps(package, default=str))
        assert_equal(len(pending), 1)
        assert pending <= funded
        assert_equal(self.reservations(venue), pending)
        # Promote the documented memory reservation; the retained package is the
        # operator record, not a claim that btxd durably stores an unsigned queue.
        venue.lockunspent(False, rpc_outpoints(pending), True)
        other = {next(iter(funded - pending))}
        available = funded - pending - other
        venue.lockunspent(False, rpc_outpoints(other), True)
        assert_equal(self.reservations(venue), pending | other)
        node.unloadwallet("venue")
        node.loadwallet("venue")
        assert_equal(self.reservations(node.get_wallet_rpc("venue")), pending | other)
        self.restart_node(0)
        node = self.nodes[0]
        for name in ("miner", "source", "venue"):
            if name not in node.listwallets():
                node.loadwallet(name)
        venue = node.get_wallet_rpc("venue")
        assert_equal(venue.getwalletinfo()["private_keys_enabled"], False)
        retained_package = json.loads(package_file.read_text())
        assert_equal(selected(retained_package), pending)
        assert_equal(self.reservations(venue), pending | other)
        for txid, vout in pending | other:
            assert node.gettxout(txid, vout) is not None
        fresh_package = venue.createexchangebatch(pay, options)
        assert_equal(selected(fresh_package), available)
        assert not selected(fresh_package) & pending
        # Construction stays refused while every coin is allocated.
        assert_raises_rpc_error(-4, "Insufficient funds", venue.createexchangebatch, pay, options)
        venue.lockunspent(True, rpc_outpoints(pending))
        assert_equal(self.reservations(venue), other | available)
        replacement = venue.createexchangebatch(pay, options)
        assert_equal(selected(replacement), pending)
        venue.lockunspent(True, rpc_outpoints(pending))
        self.restart_node(0)
        node = self.nodes[0]
        for name in ("miner", "source", "venue"):
            if name not in node.listwallets():
                node.loadwallet(name)
        venue = node.get_wallet_rpc("venue")
        assert_equal(self.reservations(venue), other)
        venue.lockunspent(True, rpc_outpoints(other))

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        node.createwallet("source")
        node.createwallet("venue", disable_private_keys=True, blank=True)
        miner = node.get_wallet_rpc("miner")
        source = node.get_wallet_rpc("source")
        self.mining_address = miner.getnewaddress()
        self.generatetoaddress(node, 110, self.mining_address)
        public_keys = [source.getaddressinfo(source.getnewaddress())["pubkey"] for _ in range(4)]
        self.addresses = [node.deriveaddresses(f"mr({key})", None,
                          {"require_checksum": False})[0] for key in public_keys]
        venue = node.get_wallet_rpc("venue")
        venue.importdepositpool([{"pubkey": key, "index": index}
                                 for index, key in enumerate(public_keys)])
        self.log.info("Restore an older watch-only backup using retained later inventory")
        self.inventory_recovery()
        self.log.info("Reconcile a missed fork and new receipt without restarting")
        self.listener_recovery()
        self.log.info("Retained unsigned package reservations survive reload and restart")
        self.pending_recovery()


if __name__ == '__main__':
    WalletCustodyRecoveryTest(__file__).main()
