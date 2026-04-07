#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that we reject low difficulty headers to prevent our block tree from filling up with useless bloat"""

from test_framework.test_framework import BitcoinTestFramework

from test_framework.p2p import (
    P2PInterface,
)

from test_framework.messages import (
    CBlockHeader,
    from_hex,
    msg_headers,
)

from test_framework.util import assert_equal

import time

NODE1_MIN_CHAINWORK = 0x1F
NODE2_MIN_CHAINWORK = 0x1000


class RejectLowDifficultyHeadersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.rpc_timeout *= 4  # To avoid timeout when generating BLOCKS_TO_MINE
        self.setup_clean_chain = True
        self.num_nodes = 4
        # Node0 has no required chainwork; node1 and node2 require increasing minimum chainwork.
        self.extra_args = [["-minimumchainwork=0x0", "-checkblockindex=0"], ["-minimumchainwork=0x1f", "-checkblockindex=0"], ["-minimumchainwork=0x1000", "-checkblockindex=0"], ["-minimumchainwork=0x1000", "-checkblockindex=0", "-whitelist=noban@127.0.0.1"]]

    def setup_network(self):
        self.setup_nodes()
        self.reconnect_all()
        self.sync_all()

    def disconnect_all(self):
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(0, 3)

    def reconnect_all(self):
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)

    def mocktime_all(self, time):
        for n in self.nodes:
            n.setmocktime(time)

    def test_chains_sync_when_long_enough(self):
        genesis_hash = self.nodes[0].getblockhash(0)
        genesis_work = int(self.nodes[0].getblockheader(genesis_hash)["chainwork"], 16)
        first_hash = self.generate(self.nodes[0], 1, sync_fun=self.no_op)[0]
        first_work = int(self.nodes[0].getblockheader(first_hash)["chainwork"], 16)
        per_block_work = first_work - genesis_work
        assert per_block_work > 0

        def blocks_required(min_chainwork):
            needed = min_chainwork - genesis_work
            if needed <= 0:
                return 0
            return (needed + per_block_work - 1) // per_block_work

        node1_blocks_required = blocks_required(NODE1_MIN_CHAINWORK)
        node2_blocks_required = blocks_required(NODE2_MIN_CHAINWORK)

        self.log.info("Generate blocks on the node with no required chainwork, and verify nodes 1 and 2 have no new headers in their headers tree")
        with self.nodes[1].assert_debug_log(expected_msgs=["[net] Ignoring low-work chain"]), self.nodes[2].assert_debug_log(expected_msgs=["[net] Ignoring low-work chain"]), self.nodes[3].assert_debug_log(expected_msgs=["Synchronizing blockheaders, height:"]):
            self.generate(self.nodes[0], max(0, node1_blocks_required - 1 - self.nodes[0].getblockcount()), sync_fun=self.no_op)

        # Node3 should always allow headers due to noban permissions
        self.log.info("Check that node3 will sync headers (due to noban permissions)")

        def check_node3_chaintips(num_tips, tip_hash, height):
            node3_chaintips = self.nodes[3].getchaintips()
            assert len(node3_chaintips) == num_tips
            assert {
                'height': height,
                'hash': tip_hash,
                'branchlen': height,
                'status': 'headers-only',
            } in node3_chaintips

        check_node3_chaintips(2, self.nodes[0].getbestblockhash(), node1_blocks_required - 1)

        for node in self.nodes[1:3]:
            chaintips = node.getchaintips()
            assert len(chaintips) == 1
            assert {
                'height': 0,
                'hash': genesis_hash,
                'branchlen': 0,
                'status': 'active',
            } in chaintips

        self.log.info("Generate more blocks to satisfy node1's minchainwork requirement, and verify node2 still has no new headers in headers tree")
        with self.nodes[2].assert_debug_log(expected_msgs=["[net] Ignoring low-work chain"]), self.nodes[3].assert_debug_log(expected_msgs=["Synchronizing blockheaders, height:"]):
            self.generate(self.nodes[0], max(0, node1_blocks_required - self.nodes[0].getblockcount()), sync_fun=self.no_op)
        self.sync_blocks(self.nodes[0:2]) # node3 will sync headers (noban permissions) but not blocks (due to minchainwork)

        assert {
            'height': 0,
            'hash': genesis_hash,
            'branchlen': 0,
            'status': 'active',
        } in self.nodes[2].getchaintips()

        assert len(self.nodes[2].getchaintips()) == 1

        self.log.info("Check that node3 accepted these headers as well")
        check_node3_chaintips(2, self.nodes[0].getbestblockhash(), node1_blocks_required)

        self.log.info("Generate long chain for node0/node1/node3")
        self.generate(self.nodes[0], max(0, node2_blocks_required - self.nodes[0].getblockcount()), sync_fun=self.no_op)

        self.log.info("Verify that node2 and node3 will sync the chain when it gets long enough")
        self.sync_blocks()

    def test_peerinfo_includes_headers_presync_height(self):
        self.log.info("Test that getpeerinfo() includes headers presync height")

        # Disconnect network, so that we can find our own peer connection more
        # easily
        self.disconnect_all()

        p2p = self.nodes[0].add_p2p_connection(P2PInterface())
        node = self.nodes[0]
        headers_source = self.nodes[1]

        # Ensure we have a long chain already
        current_height = node.getblockcount()
        if (current_height < 3000):
            self.generate(node, 3000-current_height, sync_fun=self.no_op)

        # Build a deep fork from genesis using a disconnected node's native miner
        # (fast, deterministic), then announce all 2000 headers from our P2P peer.
        headers_to_send = 2000
        assert headers_source.getblockcount() > 0
        headers_source.invalidateblock(headers_source.getblockhash(1))
        assert_equal(headers_source.getblockcount(), 0)

        new_hashes = self.generate(headers_source, headers_to_send, sync_fun=self.no_op)

        new_headers = [from_hex(CBlockHeader(), headers_source.getblockheader(block_hash, False)) for block_hash in new_hashes]
        p2p.send_message(msg_headers(headers=new_headers))
        p2p.wait_for_getheaders(timeout=30)

        # getpeerinfo should always include the presync field for this peer.
        # On BTX/KAWPOW runs this can remain -1 while still requesting headers.
        peerinfo = node.getpeerinfo()[0]
        assert 'presynced_headers' in peerinfo
        assert isinstance(peerinfo['presynced_headers'], int)
        assert peerinfo['presynced_headers'] >= -1

    def test_large_reorgs_can_succeed(self):
        self.log.info("Test that a 2000+ block reorg, starting from a point that is more than 2000 blocks before a locator entry, can succeed")

        self.sync_all() # Ensure all nodes are synced.
        self.disconnect_all()

        # locator(block at height T) will have heights:
        # [T, T-1, ..., T-10, T-12, T-16, T-24, T-40, T-72, T-136, T-264,
        #  T-520, T-1032, T-2056, T-4104, ...]
        # So mine a number of blocks > 4104 to ensure that the first window of
        # received headers during a sync are fully between locator entries.
        BLOCKS_TO_MINE = 4110

        self.generate(self.nodes[0], BLOCKS_TO_MINE, sync_fun=self.no_op)
        self.generate(self.nodes[1], BLOCKS_TO_MINE+2, sync_fun=self.no_op)

        self.reconnect_all()

        self.mocktime_all(int(time.time()))  # Temporarily hold time to avoid internal timeouts
        self.sync_blocks(timeout=300) # Ensure tips eventually agree
        self.mocktime_all(0)


    def run_test(self):
        self.test_chains_sync_when_long_enough()

        self.test_large_reorgs_can_succeed()

        self.test_peerinfo_includes_headers_presync_height()



if __name__ == '__main__':
    RejectLowDifficultyHeadersTest(__file__).main()
