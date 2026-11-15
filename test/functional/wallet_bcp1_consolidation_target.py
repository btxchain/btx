#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BCP/1 consolidation ends with target_utxo_count UTXOs.

planconsolidation, estimateconsolidationfee and createconsolidationtx sweep
deposit UTXOs into one output. target_utxo_count (default 1) is the number of
UTXOs the wallet ends with: the coins left out plus that one output.
"""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletBCP1ConsolidationTargetTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def venue(self, name, deposits):
        """A watch-only pool with `deposits` funded entries and one unfunded sweep address."""
        node = self.nodes[0]
        node.createwallet(wallet_name=name, disable_private_keys=True, blank=True)
        wallet = node.get_wallet_rpc(name)
        addresses = []
        entries = []
        for index in range(deposits + 1):
            pubkey = self.source.getaddressinfo(self.source.getnewaddress())["pubkey"]
            addresses.append(node.deriveaddresses(f"mr({pubkey})", None, {"require_checksum": False})[0])
            entries.append({"pubkey": pubkey, "index": index})
        wallet.importdepositpool(entries)
        for address in addresses[:deposits]:
            self.miner.sendtoaddress(address, Decimal("2"))
        self.generatetoaddress(node, 1, self.miner.getnewaddress(), sync_fun=self.no_op)
        return wallet, addresses[deposits]

    def inputs(self, wallet, sweep, **options):
        """Inputs of the plan and of the package createconsolidationtx builds with the same options."""
        options["min_confirmations"] = 1
        plan = wallet.planconsolidation(options)
        package = wallet.createconsolidationtx({**options, "change_address": sweep})
        tx = self.nodes[0].decodepsbt(package["psbt"])["tx"]
        assert_equal(len(tx["vout"]), 1)
        assert_equal(len(tx["vin"]), plan["input_count"])
        return plan["input_count"]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        self.miner = node.get_wallet_rpc("miner")
        node.createwallet("source")
        self.source = node.get_wallet_rpc("source")
        self.generatetoaddress(node, 110, self.miner.getnewaddress(), sync_fun=self.no_op)

        self.log.info("Five deposits end as one UTXO by default, and as two with target_utxo_count 2")
        five, sweep = self.venue("five", 5)
        assert_equal(self.inputs(five, sweep), 5)
        assert_equal(self.inputs(five, sweep, target_utxo_count=1), 5)
        assert_equal(self.inputs(five, sweep, target_utxo_count=2), 4)
        assert_equal(self.inputs(five, sweep, target_utxo_count=4), 2)

        self.log.info("Two deposits are swept together")
        two, sweep = self.venue("two", 2)
        assert_equal(self.inputs(two, sweep), 2)

        self.log.info("A single deposit can still be swept to another address, also with a larger target")
        one, _ = self.venue("one", 1)
        assert_equal(self.inputs(one, self.miner.getnewaddress()), 1)
        assert_equal(self.inputs(one, self.miner.getnewaddress(), target_utxo_count=2), 1)

        self.log.info("target_utxo_count must be at least 1 when the wallet selects the inputs")
        assert_raises_rpc_error(-8, "target_utxo_count must be at least 1", five.planconsolidation,
                                {"min_confirmations": 1, "target_utxo_count": 0})
        # A plan that names its own inputs does not use target_utxo_count and is not refused.
        own = five.listunspent(1)[0]
        five.planconsolidation({"min_confirmations": 1, "target_utxo_count": 0,
                                "inputs": [{"txid": own["txid"], "vout": own["vout"]}]})

        self.log.info("max_inputs and batch_size must be at least 1")
        for key in ("max_inputs", "batch_size"):
            for value in (-1, 0):
                assert_raises_rpc_error(-8, f"{key} must be at least 1", five.planconsolidation,
                                        {"min_confirmations": 1, key: value})
        assert_equal(len(five.planconsolidation({"min_confirmations": 1, "max_inputs": 2})["inputs"]), 2)


if __name__ == '__main__':
    WalletBCP1ConsolidationTargetTest(__file__).main()
