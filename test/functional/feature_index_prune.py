#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test indices in conjunction with prune."""
import concurrent.futures
import os
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class FeatureIndexPruneTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [
            ["-fastprune", "-prune=1", "-blockfilterindex=1"],
            ["-fastprune", "-prune=1", "-coinstatsindex=1"],
            ["-fastprune", "-prune=1", "-blockfilterindex=1", "-coinstatsindex=1"],
            [],
        ]

    def setup_network(self):
        self.setup_nodes()  # No P2P connection, so that linear_sync works

    def linear_sync(self, node_from, *, height_from=None):
        # Linear sync over RPC, because P2P sync may not be linear
        to_height = node_from.getblockcount()
        if height_from is None:
            height_from = min([n.getblockcount() for n in self.nodes]) + 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_nodes) as rpc_threads:
            for i in range(height_from, to_height + 1):
                b = node_from.getblock(blockhash=node_from.getblockhash(i), verbosity=0)
                list(rpc_threads.map(lambda n: n.submitblock(b), self.nodes))

    def generate(self, node, num_blocks, sync_fun=None):
        return super().generate(node, num_blocks, sync_fun=sync_fun or (lambda: self.linear_sync(node)))

    def sync_index(self, height):
        expected_filter = {
            'basic block filter index': {'synced': True, 'best_block_height': height},
        }
        self.wait_until(lambda: self.nodes[0].getindexinfo() == expected_filter)

        expected_stats = {
            'coinstatsindex': {'synced': True, 'best_block_height': height}
        }
        self.wait_until(lambda: self.nodes[1].getindexinfo() == expected_stats, timeout=150)

        expected = {**expected_filter, **expected_stats}
        self.wait_until(lambda: self.nodes[2].getindexinfo() == expected)

    def restart_without_indices(self):
        for i in range(3):
            self.restart_node(i, extra_args=["-fastprune", "-prune=1"])

    def run_test(self):
        filter_nodes = [self.nodes[0], self.nodes[2]]
        stats_nodes = [self.nodes[1], self.nodes[2]]

        self.log.info("check if we can access blockfilters and coinstats when pruning is enabled but no blocks are actually pruned")
        self.sync_index(height=200)
        tip = self.nodes[0].getbestblockhash()
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(tip)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=tip)['muhash']

        self.generate(self.nodes[0], 500)
        self.sync_index(height=700)

        self.log.info("prune some blocks")
        for node in self.nodes[:2]:
            with node.assert_debug_log(['Prune: UnlinkPrunedFiles deleted blk/rev']):
                pruneheight_new = node.pruneblockchain(400)
                # The exact height is a block-file boundary and therefore depends on BTX block
                # serialization. The RPC contract is that pruning stops at or below the request.
                assert_greater_than(pruneheight_new, 0)
                assert pruneheight_new <= 400
                # pruneblockchain returns the last pruned height, while
                # getblockchaininfo reports the first retained height.
                assert_equal(node.getblockchaininfo()['pruneheight'], pruneheight_new + 1)

        self.log.info("check if we can access the tips blockfilter and coinstats when we have pruned some blocks")
        tip = self.nodes[0].getbestblockhash()
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(tip)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=tip)['muhash']

        self.log.info("check if we can access the blockfilter and coinstats of a pruned block")
        height_hash = self.nodes[0].getblockhash(2)
        for node in self.nodes[:2]:
            assert_raises_rpc_error(-1, "Block not available (pruned data)", node.getblock, height_hash, 0)
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(height_hash)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=height_hash)['muhash']

        # mine and sync index up to a height that will later be the pruneheight
        self.generate(self.nodes[0], 51)
        self.sync_index(height=751)

        # Index-owned prune locks are deliberately temporary and disappear
        # while an index is disabled. Install an explicit persistent lock to
        # model the intended resume boundary across the restart below.
        index_best_height = 751
        for node in self.nodes[:3]:
            assert node.setprunelock("index-resume", {
                "desc": "Preserve the disabled-index resume boundary",
                "height": [index_best_height, index_best_height],
                "sync": True,
            })["success"]

        self.restart_without_indices()

        self.log.info("make sure trying to access the indices throws errors")
        for node in filter_nodes:
            msg = "Index is not enabled for filtertype basic"
            assert_raises_rpc_error(-1, msg, node.getblockfilter, height_hash)
        for node in stats_nodes:
            msg = "Querying specific block heights requires coinstatsindex"
            assert_raises_rpc_error(-8, msg, node.gettxoutsetinfo, "muhash", height_hash)

        self.generate(self.nodes[0], 749)

        self.log.info("prune request beyond, but actual pruning below, the indices best blocks while indices are disabled")
        for i in range(3):
            pruneheight_2 = self.nodes[i].pruneblockchain(1000)
            assert_greater_than(pruneheight_2, 0)
            assert pruneheight_2 < index_best_height
            assert_equal(self.nodes[i].getblockchaininfo()['pruneheight'], pruneheight_2 + 1)
            # Restart the nodes again with the indices activated
            self.restart_node(i, extra_args=self.extra_args[i])

        self.log.info("make sure that we can continue with the partially synced indices after having pruned up to the index height")
        self.sync_index(height=1500)
        for node in self.nodes[:3]:
            assert node.setprunelock("index-resume", {})["success"]

        self.log.info("prune further than the indices best blocks while the indices are disabled")
        self.restart_without_indices()
        self.generate(self.nodes[0], 1000)

        for i in range(3):
            pruneheight_3 = self.nodes[i].pruneblockchain(2000)
            assert_greater_than(pruneheight_3, 1500)
            assert pruneheight_3 <= 2000
            assert_equal(self.nodes[i].getblockchaininfo()['pruneheight'], pruneheight_3 + 1)
            self.stop_node(i)

        self.log.info("make sure we get an init error when starting the nodes again with the indices")
        filter_msg = "Error: basic block filter index best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)"
        stats_msg = "Error: coinstatsindex best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)"
        end_msg = f"{os.linesep}Error: A fatal internal error occurred, see debug.log for details: Failed to start indexes, shutting down.."
        for i, msg in enumerate([filter_msg, stats_msg, filter_msg]):
            self.nodes[i].assert_start_raises_init_error(extra_args=self.extra_args[i], expected_msg=msg+end_msg)

        self.log.info("make sure the nodes start again with the indices and an additional -reindex arg")
        for i in range(3):
            restart_args = self.extra_args[i] + ["-reindex"]
            self.restart_node(i, extra_args=restart_args)

        self.linear_sync(self.nodes[3])
        self.sync_index(height=2500)

        for node in self.nodes[:2]:
            previous_pruneheight = node.getblockchaininfo()['pruneheight']
            with node.assert_debug_log(['Prune: UnlinkPrunedFiles deleted blk/rev']):
                pruneheight_new = node.pruneblockchain(2500)
                assert_greater_than(pruneheight_new + 1, previous_pruneheight)
                # Manual pruning retains at least 288 blocks. The returned height is the
                # last block in a fully pruned file and may be lower than this cap.
                assert pruneheight_new <= 2500 - 288
                assert_equal(node.getblockchaininfo()['pruneheight'], pruneheight_new + 1)

        self.log.info("ensure that prune locks don't prevent indices from failing in a reorg scenario")
        with self.nodes[0].assert_debug_log(['basic block filter index prune lock moved back to 2480']):
            self.nodes[3].invalidateblock(self.nodes[0].getblockhash(2480))
            self.generate(self.nodes[3], 30, sync_fun=lambda: self.linear_sync(self.nodes[3], height_from=2480))


if __name__ == '__main__':
    FeatureIndexPruneTest(__file__).main()
