#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""importdepositpool {"rescan": true} must not report a rescan that could not cover the chain.

node0 keeps every block, node1 prunes. A deposit sits in an early block. On node1 the
rescan cannot read that block, so the import with rescan is refused before anything is
imported; the import without rescan still works. On node0 the rescan finds the deposit.
"""
from decimal import Decimal

from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletBCP1DepositPoolRescanTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        base = list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]
        self.extra_args = [base, base + ["-prune=1", "-fastprune"]]
        self.rpc_timeout = 300

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        full, pruned = self.nodes
        full.createwallet("source")
        deposit = full.get_wallet_rpc("source").getnewaddress()
        full.createwallet("miner")
        miner = full.get_wallet_rpc("miner")
        self.generatetoaddress(full, 105, miner.getnewaddress())
        miner.sendtoaddress(deposit, Decimal("5"))
        self.generatetoaddress(full, 1, miner.getnewaddress())
        for _ in range(8):
            self.generatetoaddress(full, 50, miner.getnewaddress())

        pruned.pruneblockchain(pruned.getblockcount() - 300)
        assert pruned.getblockchaininfo()["pruneheight"] > 106

        self.log.info("A rescan the pruned node cannot do is refused before the import")
        pruned.createwallet(wallet_name="venue", disable_private_keys=True, blank=True)
        venue = pruned.get_wallet_rpc("venue")
        assert_raises_rpc_error(-4, "Pruned blocks from height 0 required to rescan for the deposit pool",
                                venue.importdepositpool, [deposit], {"rescan": True})
        assert_equal(venue.listdescriptors()["descriptors"], [])

        self.log.info("Without rescan the pool imports on the pruned node")
        res = venue.importdepositpool([deposit])
        assert_equal(res["success"], True)
        assert_equal(res["rescan"], False)

        self.log.info("With all blocks the rescan finds the deposit")
        full.createwallet(wallet_name="venue", disable_private_keys=True, blank=True)
        full_venue = full.get_wallet_rpc("venue")
        res = full_venue.importdepositpool([deposit], {"rescan": True})
        assert_equal(res["rescan"], True)
        assert_equal(full_venue.getreceivedbyaddress(deposit, 0), Decimal("5"))


if __name__ == "__main__":
    WalletBCP1DepositPoolRescanTest(__file__).main()
