#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Watch-only deposit accounting survives reload and clean restart exactly."""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, find_vout_for_address


class WalletBCP1RecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + [
            "-autoshieldcoinbase=0"]]

    def setup_network(self):
        if self.config["components"].getboolean("ENABLE_MODELNET", fallback=False):
            self.extra_args[0].append("-nomodelnet")
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_accounting(self, expected):
        node = self.nodes[0]
        node.syncwithvalidationinterfacequeue()
        venue = node.get_wallet_rpc("venue")
        info = venue.getwalletinfo()
        assert_equal(info["private_keys_enabled"], False)
        assert_equal(info["descriptors"], True)
        for (txid, vout), fields in expected.items():
            actual = venue.getdepositstatus(txid, vout)
            assert_equal(actual["txid"], txid)
            assert_equal(actual["vout"], vout)
            assert_equal(actual["irreversible"], False)
            for key, value in fields.items():
                if key != "spent_by":
                    assert_equal(actual[key], value)
        for include_spent in (False, True):
            rows = venue.listdepositutxos({"include_spent": include_spent})
            by_outpoint = {(r["txid"], r["vout"]): r for r in rows}
            assert_equal(len(by_outpoint), len(rows))
            wanted = {outpoint: fields for outpoint, fields in expected.items()
                      if fields["status"] == "CONFIRMED" or
                      (include_spent and fields["status"] == "SPENT")}
            assert_equal(set(by_outpoint), set(wanted))
            for outpoint, fields in wanted.items():
                for key, value in fields.items():
                    assert_equal(by_outpoint[outpoint][key], value)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        node.createwallet("source")
        node.createwallet("venue", disable_private_keys=True, blank=True)
        miner = node.get_wallet_rpc("miner")
        source = node.get_wallet_rpc("source")
        venue = node.get_wallet_rpc("venue")
        mining_address = miner.getnewaddress()
        self.generatetoaddress(node, 110, mining_address)
        addresses = [source.getnewaddress() for _ in range(5)]
        venue.importdepositpool([{"address": a, "index": i} for i, a in enumerate(addresses)])
        deposits = []
        for address in addresses[:3]:
            txid = miner.sendtoaddress(address, Decimal("2"))
            vout = find_vout_for_address(node, txid, address)
            deposits.append((txid, vout))
        deposit_block = self.generatetoaddress(node, 1, mining_address)[0]
        spender = source.send(outputs=[{mining_address: Decimal("1")}], options={
            "inputs": [{"txid": deposits[0][0], "vout": deposits[0][1]}],
            "add_inputs": False})["txid"]
        replaced = miner.send(outputs=[{addresses[3]: Decimal("2")}],
                              options={"replaceable": True})["txid"]
        replaced_outpoint = (replaced, find_vout_for_address(node, replaced, addresses[3]))
        replacement = miner.bumpfee(replaced)["txid"]
        replacement_outpoint = (replacement, find_vout_for_address(node, replacement, addresses[3]))
        conflict_block = self.generatetoaddress(node, 1, mining_address)[0]

        expected = {}
        def row(outpoint, address, status, block, spent_by=None):
            height = node.getblockheader(block)["height"]
            depth = node.getblockcount() - height + 1
            fields = dict(address=address, amount_atoms=200000000, status=status,
                          block_hash=block, block_height=height,
                          confirmations=-depth if status == "CONFLICTED" else depth)
            if spent_by is not None:
                fields["spent_by"] = spent_by
            expected[outpoint] = fields
        for i, outpoint in enumerate(deposits):
            row(outpoint, addresses[i], "SPENT" if i == 0 else "CONFIRMED",
                deposit_block, spender if i == 0 else None)
        row(replaced_outpoint, addresses[3], "CONFLICTED", conflict_block)
        row(replacement_outpoint, addresses[3], "CONFIRMED", conflict_block)
        self.log.info("Exact accounting before and after wallet reload")
        self.assert_accounting(expected)
        node.unloadwallet("venue")
        node.loadwallet("venue")
        self.assert_accounting(expected)

        self.log.info("Reconcile a disconnected deposit while the node stays up")
        txid = miner.sendtoaddress(addresses[4], Decimal("2"))
        outpoint = (txid, find_vout_for_address(node, txid, addresses[4]))
        reorg_block = self.generatetoaddress(node, 1, mining_address)[0]
        venue = node.get_wallet_rpc("venue")
        assert_equal(venue.getdepositstatus(*outpoint)["status"], "CONFIRMED")
        node.invalidateblock(reorg_block)
        node.syncwithvalidationinterfacequeue()
        reorged = venue.getdepositstatus(*outpoint)
        assert_equal(reorged["status"], "REORGED")
        assert_equal(reorged["confirmations"], 0)
        node.reconsiderblock(reorg_block)
        node.syncwithvalidationinterfacequeue()
        for fields in expected.values():
            fields["confirmations"] += -1 if fields["status"] == "CONFLICTED" else 1
        row(outpoint, addresses[4], "CONFIRMED", reorg_block)
        self.assert_accounting(expected)
        tip = node.getbestblockhash()
        self.restart_node(0)
        for name in ("miner", "source", "venue"):
            if name not in self.nodes[0].listwallets():
                self.nodes[0].loadwallet(name)
        assert_equal(self.nodes[0].getbestblockhash(), tip)
        self.log.info("Exact accounting after a clean restart at the same tip")
        self.assert_accounting(expected)


if __name__ == '__main__':
    WalletBCP1RecoveryTest(__file__).main()
