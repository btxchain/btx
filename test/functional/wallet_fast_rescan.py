#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that fast rescan using block filters for descriptor wallets detects
   top-ups correctly and finds the same transactions than the slow variant."""
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal


KEYPOOL_SIZE = 100  # smaller than default size to speed-up test
NUM_BLOCKS = 6      # number of blocks to mine


class WalletFastRescanTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def get_wallet_txids(self, node: TestNode, wallet_name: str) -> list[str]:
        w = node.get_wallet_rpc(wallet_name)
        txs = w.listtransactions('*', 1000000)
        return [tx['txid'] for tx in txs]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create descriptor wallet with backup")
        WALLET_BACKUP_FILENAME = node.datadir_path / 'wallet.bak'
        node.createwallet(wallet_name='funder', descriptors=True)
        funder = node.get_wallet_rpc('funder')
        node.createwallet(wallet_name='topup_test', descriptors=True)
        w = node.get_wallet_rpc('topup_test')
        descriptors = w.listdescriptors()['descriptors']
        assert descriptors
        watchonly_import_supported = not any("mr(" in descriptor["desc"] for descriptor in descriptors)
        w.backupwallet(WALLET_BACKUP_FILENAME)

        self.log.info("Fund a dedicated sender wallet with mature coinbase outputs")
        self.generatetoaddress(node, COINBASE_MATURITY + 1, funder.getnewaddress())
        expected_tx_count = 2 * NUM_BLOCKS

        self.log.info("Create txs sending to end range address of each descriptor, triggering top-ups")
        for i in range(NUM_BLOCKS):
            self.log.info(f"Block {i+1}/{NUM_BLOCKS}")
            external_addr = ""
            internal_addr = ""
            for _ in range(KEYPOOL_SIZE):
                external_addr = w.getnewaddress()
                internal_addr = w.getrawchangeaddress()
            assert external_addr and internal_addr
            for label, addr in (("external-end", external_addr), ("internal-end", internal_addr)):
                self.log.info(f"-> {label} descriptor address {addr}")
                funder.sendtoaddress(addr, Decimal("0.0001"))
            self.generate(node, 1)

        self.log.info("Import wallet backup with block filter index")
        with node.assert_debug_log(['fast variant using block filters']):
            node.restorewallet('rescan_fast', WALLET_BACKUP_FILENAME)
        txids_fast = self.get_wallet_txids(node, 'rescan_fast')

        self.log.info("Import non-active descriptors with block filter index")
        node.createwallet(wallet_name='rescan_fast_nonactive', descriptors=True, disable_private_keys=True, blank=True)
        w = node.get_wallet_rpc('rescan_fast_nonactive')
        w.importdescriptors([{"desc": descriptor['desc'], "timestamp": 0} for descriptor in descriptors])
        txids_fast_nonactive = self.get_wallet_txids(node, 'rescan_fast_nonactive')

        self.restart_node(0, [f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=0'])
        self.log.info("Import wallet backup w/o block filter index")
        with node.assert_debug_log(['slow variant inspecting all blocks']):
            node.restorewallet("rescan_slow", WALLET_BACKUP_FILENAME)
        txids_slow = self.get_wallet_txids(node, 'rescan_slow')

        self.log.info("Import non-active descriptors w/o block filter index")
        node.createwallet(wallet_name='rescan_slow_nonactive', descriptors=True, disable_private_keys=True, blank=True)
        w = node.get_wallet_rpc('rescan_slow_nonactive')
        w.importdescriptors([{"desc": descriptor['desc'], "timestamp": 0} for descriptor in descriptors])
        txids_slow_nonactive = self.get_wallet_txids(node, 'rescan_slow_nonactive')

        self.log.info("Verify that all rescans found the same txs in slow and fast variants")
        assert_equal(len(txids_slow), expected_tx_count)
        assert_equal(len(txids_fast), expected_tx_count)
        if watchonly_import_supported:
            assert_equal(len(txids_slow_nonactive), expected_tx_count)
            assert_equal(len(txids_fast_nonactive), expected_tx_count)
        else:
            self.log.info("BTX descriptor export includes watch-only-incompatible P2MR entries; compare non-active fast/slow results without exact-count expectations")
        assert_equal(sorted(txids_slow), sorted(txids_fast))
        assert_equal(sorted(txids_slow_nonactive), sorted(txids_fast_nonactive))


if __name__ == '__main__':
    WalletFastRescanTest(__file__).main()
